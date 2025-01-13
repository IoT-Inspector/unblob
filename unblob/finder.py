"""Searching Chunk related functions.

The main "entry point" is search_chunks_by_priority.
"""

from functools import lru_cache
from typing import Optional

import attrs
from pyperscan import Flag, Pattern, Scan, StreamDatabase
from structlog import get_logger

from .file_utils import DEFAULT_BUFSIZE, InvalidInputFormat, SeekError
from .handlers import Handlers
from .models import File, Handler, TaskResult, ValidChunk
from .parser import InvalidHexString
from .report import CalculateChunkExceptionReport

logger = get_logger()


@attrs.define
class HyperscanMatchContext:
    file: File
    file_size: int
    all_chunks: list
    task_result: TaskResult
    start_offset: int


def _calculate_chunk(
    handler: Handler, file: File, real_offset, task_result: TaskResult
) -> Optional[ValidChunk]:
    file.seek(real_offset)
    try:
        return handler.calculate_chunk(file, real_offset)
    except InvalidInputFormat as exc:
        logger.debug(
            "File format is invalid",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except EOFError as exc:
        logger.debug(
            "File ends before header could be read",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except SeekError as exc:
        logger.debug(
            "Seek outside file during chunk calculation",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except Exception as exc:
        error_report = CalculateChunkExceptionReport(
            handler=handler.NAME,
            start_offset=real_offset,
            exception=exc,
        )
        task_result.add_report(error_report)
        logger.error(
            "Unhandled Exception during chunk calculation", **error_report.asdict()
        )


def _hyperscan_match(
    context: HyperscanMatchContext, handler: Handler, offset: int, end: int
) -> Scan:
    del end  # unused argument
    offset += context.start_offset
    real_offset = offset + handler.PATTERN_MATCH_OFFSET

    if real_offset < 0:
        return Scan.Continue

    # Skip chunk calculation if this would start inside another one,
    # similar to remove_inner_chunks, but before we even begin calculating.
    if any(chunk.contains_offset(real_offset) for chunk in context.all_chunks):
        logger.debug(
            "Skip chunk calculation as pattern is inside an other chunk",
            handler=handler.NAME,
            offset=real_offset,
            _verbosity=2,
        )
        return Scan.Continue

    logger.debug(
        "Calculating chunk for pattern match",
        start_offset=offset,
        real_offset=real_offset,
        _verbosity=2,
        handler=handler.NAME,
    )

    chunk = _calculate_chunk(handler, context.file, real_offset, context.task_result)

    # We found some random bytes this handler couldn't parse
    if chunk is None:
        return Scan.Continue

    if chunk.end_offset > context.file_size:
        logger.debug("Chunk overflows file", chunk=chunk, _verbosity=2)
        return Scan.Continue

    chunk.handler = handler
    logger.debug("Found valid chunk", chunk=chunk, handler=handler.NAME, _verbosity=1)
    context.all_chunks.append(chunk)
    context.start_offset = chunk.end_offset

    return Scan.Terminate


def stream_scan_chunks(scanner, file: File, context: HyperscanMatchContext):
    """Scan the whole file by increment of DEFAULT_BUFSIZE using Hyperscan's streaming mode."""
    i = context.start_offset
    with memoryview(file) as data:
        while i < file.size():
            if scanner.scan(data[i : i + DEFAULT_BUFSIZE]) == Scan.Terminate:
                scanner.reset()
                i = context.start_offset
            else:
                i += DEFAULT_BUFSIZE


def search_chunks(
    file: File,
    file_size: int,
    handlers: Handlers,
    task_result: TaskResult,
) -> list[ValidChunk]:
    """Search all ValidChunks within the file.

    Search for patterns and run Handler.calculate_chunk() on the found
    matches.  We don't deal with offset within already found
    ValidChunks and invalid chunks are thrown away.  If chunk covers
    the whole file we stop any further search and processing.
    """
    all_chunks = []

    hyperscan_db = build_hyperscan_database(handlers)

    hyperscan_context = HyperscanMatchContext(
        file=file,
        file_size=file_size,
        all_chunks=all_chunks,
        task_result=task_result,
        start_offset=0,
    )

    scanner = hyperscan_db.build(hyperscan_context, _hyperscan_match)  # type: ignore

    try:
        stream_scan_chunks(scanner, file, hyperscan_context)
    except Exception as e:
        logger.error(
            "Error scanning for patterns",
            error=e,
        )

    logger.debug(
        "Ended searching for chunks",
        all_chunks=all_chunks,
    )

    return all_chunks


@lru_cache
def build_hyperscan_database(handlers: Handlers) -> StreamDatabase:
    patterns = []
    for handler_class in handlers:
        handler = handler_class()
        for pattern in handler.PATTERNS:
            try:
                patterns.append(
                    Pattern(
                        pattern.as_regex(),
                        Flag.SOM_LEFTMOST,
                        Flag.DOTALL,
                        tag=handler,
                    )
                )
            except InvalidHexString as e:
                logger.error(
                    "Invalid pattern",
                    handler=handler.NAME,
                    pattern=pattern,
                    error=str(e),
                )
                raise
    return StreamDatabase(*patterns)
