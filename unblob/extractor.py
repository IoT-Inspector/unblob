import io
import shlex
import subprocess
from pathlib import Path

from structlog import get_logger

from .models import Chunk, Handler

logger = get_logger()


class ExtractionFailed(Exception):
    pass


APPEND_NAME = "_extract"


def make_extract_dir(root: Path, path: Path, extract_root: Path) -> Path:
    """Create extraction dir under root with the name of path."""
    relative_path = path.relative_to(root)
    extract_name = relative_path.name + APPEND_NAME
    extract_dir = extract_root / relative_path.with_name(extract_name)
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Created extraction dir", path=extract_dir)
    return extract_dir.expanduser().resolve()


def carve_chunk_to_file(
    extract_dir: Path, file: io.BufferedReader, chunk: Chunk
) -> Path:
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    chunk_name = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
    logger.info("Extracting chunk", chunk=chunk, extract_dir=extract_dir)
    carved_file_path = extract_dir / chunk_name
    file.seek(chunk.start_offset)
    # FIXME: use iterators, don't read the whole file to memory
    carved_chunk = file.read(chunk.size)
    carved_file_path.write_bytes(carved_chunk)
    return carved_file_path


def extract_with_command(
    extract_dir: Path, carved_path: Path, handler: Handler
) -> Path:
    content_dir = extract_dir / (carved_path.name + APPEND_NAME)
    # We only extract every blob once, it's a mistake to extract the same blog again
    content_dir.mkdir(parents=True)

    inpath = carved_path.expanduser().resolve()
    outdir = content_dir.expanduser().resolve()
    cmd = handler.make_extract_command(str(inpath), str(outdir))

    logger.info("Running extract command", command=shlex.join(cmd))
    try:
        res = subprocess.run(
            cmd, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode != 0:
            logger.error("Extract command failed", stdout=res.stdout, stderr=res.stderr)
            raise ExtractionFailed
    except FileNotFoundError:
        logger.exception(
            "FileNotFoundError - Can't run extract command. Is the extractor installed?"
        )
        raise
    except Exception:
        logger.exception("Unhandled exception while trying to run extraction")
        raise

    return content_dir
