from typing import Optional

import attrs
from pyperscan import Flag, Pattern, Scan, StreamDatabase
from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import InvalidInputFormat, SeekError, StructParser, stream_scan
from ...models import File, Handler, HexString, Regex, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct stream_header {
        char magic[2];              // 'BZ' signature/magic number
        uint8 version;              // 'h' 0x68 for Bzip2 ('H'uffman coding), '0' for Bzip1 (deprecated)
        uint8 hundred_k_blocksize;  // '1'..'9' block-size 100 kB-900 kB (uncompressed)
    } stream_header_t;

    typedef struct block_header {
        char magic[6];              // 0x314159265359 (BCD (pi))
        uint32 crc;                 // checksum for this block
        uint8 randomised;           // 0=>normal, 1=>randomised (deprecated)
    } block_header_t;
"""


STREAM_MAGIC = b"BZ"
HUFFMAN_VERSION = ord("h")
HUNDRED_K_BLOCK_MIN = ord("1")
HUNDRED_K_BLOCK_MAX = ord("9")

# 0x314159265359 (BCD (pi))
BLOCK_MAGIC = b"1AY&SY"

# Stream ends with a magic 0x177245385090 though it is not aligned
# to byte offsets, so we pre-calculated all possible 8 shifts
# for bit_shift in range(8):
#   print(hex(0x1772_4538_5090 << bit_shift))
STREAM_END_MAGIC_PATTERNS = [
    HexString("17 72 45 38 50 90"),
    HexString("2e e4 8a 70 a1 2?"),
    HexString("5d c9 14 e1 42 4?"),
    HexString("bb 92 29 c2 84 8?"),
    HexString("?1 77 24 53 85 09"),
    HexString("?2 ee 48 a7 0a 12"),
    HexString("?5 dc 91 4e 14 24"),
    HexString("?b b9 22 9c 28 48"),
]

# 6 bytes magic + 4 bytes combined CRC
STREAM_FOOTER_SIZE = 6 + 4


def build_stream_end_scan_db(pattern_list):
    return StreamDatabase(
        *(Pattern(p.as_regex(), Flag.SOM_LEFTMOST, Flag.DOTALL) for p in pattern_list)
    )


hyperscan_stream_end_magic_db = build_stream_end_scan_db(STREAM_END_MAGIC_PATTERNS)
parser = StructParser(C_DEFINITIONS)


@attrs.define
class Bzip2SearchContext:
    start_offset: int
    file: File
    end_block_offset: int


def _validate_stream_header(file: File):
    try:
        header = parser.cparser_be.stream_header_t(file)
    except EOFError:
        return False

    return (
        header.magic == STREAM_MAGIC
        and header.version == HUFFMAN_VERSION
        and HUNDRED_K_BLOCK_MIN <= header.hundred_k_blocksize <= HUNDRED_K_BLOCK_MAX
    )


def _validate_block_header(file: File):
    try:
        header = parser.cparser_be.block_header_t(file)
    except EOFError:
        return False

    return header.magic == BLOCK_MAGIC


def _hyperscan_match(
    context: Bzip2SearchContext, pattern_id: int, offset: int, end: int
) -> Scan:
    del end  # unused argument
    # Ignore any match before the start of this chunk
    if offset < context.start_offset:
        return Scan.Continue

    last_block_end = offset + STREAM_FOOTER_SIZE
    if pattern_id > 3:
        last_block_end += 1

    # We try seek to the end of the stream
    try:
        context.file.seek(last_block_end)
    except SeekError:
        return Scan.Terminate

    context.end_block_offset = last_block_end

    # Check if there is a next stream starting after the end of this stream
    # and try to continue processing that as well
    if _validate_stream_header(context.file) and _validate_block_header(context.file):
        return Scan.Continue

    return Scan.Terminate


class BZip2Handler(Handler):
    NAME = "bzip2"

    # magic + version + block_size + block header magic
    PATTERNS = [Regex(r"\x42\x5a\x68[\x31-\x39]\x31\x41\x59\x26\x53\x59")]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-so", stdout="bzip2.uncompressed")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        if not _validate_stream_header(file):
            raise InvalidInputFormat("Invalid bzip2 stream header")

        if not _validate_block_header(file):
            raise InvalidInputFormat("Invalid bzip2 block header")

        context = Bzip2SearchContext(
            start_offset=start_offset, file=file, end_block_offset=-1
        )

        try:
            scanner = hyperscan_stream_end_magic_db.build(context, _hyperscan_match)  # type: ignore
            stream_scan(scanner, file)
        except Exception as e:
            logger.debug(
                "Error scanning for bzip2 patterns",
                error=e,
            )

        if context.end_block_offset > 0:
            return ValidChunk(
                start_offset=start_offset, end_offset=context.end_block_offset
            )

        raise InvalidInputFormat("No valid bzip2 compression block was detected")
