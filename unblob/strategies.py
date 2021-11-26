import io
import itertools
from operator import attrgetter
from pathlib import Path
from typing import Generator, List

from structlog import get_logger

from .extractor import carve_chunk_to_file, extract_with_command, make_extract_dir
from .file_utils import LimitedStartReader
from .finder import search_chunks
from .handlers import _ALL_MODULES_BY_PRIORITY
from .logging import format_hex
from .models import Chunk, UnknownChunk

logger = get_logger()


def search_chunks_by_priority(path: Path, file: io.BufferedReader) -> List[Chunk]:
    all_chunks = []

    for priority_level, handlers in enumerate(_ALL_MODULES_BY_PRIORITY, start=1):
        logger.info("Starting priority level", priority_level=priority_level)
        yara_results = search_chunks(handlers, path)

        if yara_results:
            logger.info("Found YARA results", count=len(yara_results))

        for result in yara_results:
            handler = result.handler
            match = result.match
            for offset, identifier, string_data in match.strings:
                logger.info(
                    "Calculating chunk for YARA match",
                    start_offset=format_hex(offset),
                    identifier=identifier,
                )
                real_offset = offset + handler.YARA_MATCH_OFFSET
                limited_reader = LimitedStartReader(file, real_offset)
                chunk = handler.calculate_chunk(limited_reader, real_offset)
                # We found some random bytes this handler couldn't parse
                if chunk is None:
                    continue
                chunk.handler = handler
                log = logger.bind(chunk=chunk, handler=handler.NAME)
                log.info("Found valid chunk")
                all_chunks.append(chunk)

    return all_chunks


def remove_inner_chunks(chunks: List[Chunk]):
    """Remove all chunks from the list which are within another bigger chunks."""
    chunks_by_size = sorted(chunks, key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks_by_size[0]]
    for chunk in chunks_by_size[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)
    logger.info("Removed inner chunks", outer_chunk_count=len(outer_chunks))
    return outer_chunks


def pairwise(iterable):
    # Copied from Python 3.10
    # pairwise('ABCDEFG') --> AB BC CD DE EF FG
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


def calculate_unknown_chunks(chunks: List[Chunk], file_size: int) -> List[UnknownChunk]:
    """Calculate the empty gaps between chunks."""
    sorted_by_offset = sorted(chunks, key=attrgetter("start_offset"))

    if file_size == 0:
        return []

    if not chunks:
        return [UnknownChunk(0, file_size - 1)]

    unknown_chunks = []

    first = sorted_by_offset[0]
    if first.start_offset != 0:
        unknown_chunk = UnknownChunk(0, first.start_offset - 1)
        unknown_chunks.append(unknown_chunk)

    for chunk, next_chunk in pairwise(sorted_by_offset):
        diff = next_chunk.start_offset - chunk.end_offset
        if diff != 1:
            unknown_chunk = UnknownChunk(
                start_offset=chunk.end_offset + 1,
                end_offset=next_chunk.start_offset - 1,
            )
            unknown_chunks.append(unknown_chunk)

    last = sorted_by_offset[-1]
    if last.end_offset < file_size - 1:
        unknown_chunk = UnknownChunk(
            start_offset=last.end_offset + 1,
            end_offset=file_size - 1,
        )
        unknown_chunks.append(unknown_chunk)

    return unknown_chunks


def extract_with_priority(
    root: Path, path: Path, extract_root: Path, file_size: int
) -> Generator[Path, None, None]:

    with path.open("rb") as file:
        all_chunks = search_chunks_by_priority(path, file)
        if not all_chunks:
            return

        outer_chunks = remove_inner_chunks(all_chunks)
        unknown_chunks = calculate_unknown_chunks(outer_chunks, file_size)
        if unknown_chunks:
            logger.warning("Found unknown Chunks", chunks=unknown_chunks)

        for chunk in outer_chunks:
            extract_dir = make_extract_dir(root, path, extract_root)
            carved_path = carve_chunk_to_file(extract_dir, file, chunk)
            extracted = extract_with_command(extract_dir, carved_path, chunk.handler)
            yield extracted
