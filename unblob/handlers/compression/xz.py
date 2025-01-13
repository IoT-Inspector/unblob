import io
from typing import Optional

import attrs
from pyperscan import Flag, Pattern, Scan, StreamDatabase
from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import (
    Endian,
    convert_int8,
    convert_int16,
    convert_int32,
    decode_multibyte_integer,
    read_until_past,
    round_up,
    stream_scan,
)
from ...models import File, Handler, HexString, InvalidInputFormat, ValidChunk

logger = get_logger()

# The .xz file format definition: https://tukaani.org/xz/xz-file-format-1.0.4.txt

STREAM_START_MAGIC = b"\xfd\x37\x7a\x58\x5a\x00"

STREAM_END_MAGIC_PATTERNS = [
    HexString("00 00 59 5A"),  # None
    HexString("00 01 59 5A"),  # CRC32
    HexString("00 04 59 5A"),  # CRC64
    HexString("00 0A 59 5A"),  # SHA-256
]

NONE_STREAM_FLAG = 0x0
CRC32_STREAM_FLAG = 0x1
CRC64_STREAM_FLAG = 0x4
SHA256_STREAM_FLAG = 0xA
VALID_FLAGS = [
    NONE_STREAM_FLAG,
    CRC32_STREAM_FLAG,
    CRC64_STREAM_FLAG,
    SHA256_STREAM_FLAG,
]
BACKWARD_SIZE_LEN = 4
MAX_MBI_LEN = 9  # maximum multi-byte integer size is 9, per XZ standard
XZ_PADDING = 4  # XZ format byte alignment
FLAG_LEN = 2
EOS_MAGIC_LEN = 2
CRC32_LEN = 4
STREAM_HEADER_LEN = len(STREAM_START_MAGIC) + FLAG_LEN + CRC32_LEN
STREAM_FOOTER_LEN = CRC32_LEN + BACKWARD_SIZE_LEN + FLAG_LEN + EOS_MAGIC_LEN


def build_stream_end_scan_db(pattern_list):
    return StreamDatabase(
        *(Pattern(p.as_regex(), Flag.SOM_LEFTMOST, Flag.DOTALL) for p in pattern_list)
    )


hyperscan_stream_end_magic_db = build_stream_end_scan_db(STREAM_END_MAGIC_PATTERNS)


@attrs.define
class XZSearchContext:
    start_offset: int
    file: File
    end_streams_offset: int
    stream_flag: int


def read_multibyte_int(file: File) -> tuple[int, int]:
    """Read a multibyte integer and return the number of bytes read and the integer itself."""
    data = bytearray(file.read(MAX_MBI_LEN))
    file.seek(-MAX_MBI_LEN, io.SEEK_CUR)
    size, mbi = decode_multibyte_integer(data)
    file.seek(size, io.SEEK_CUR)
    return size, mbi


def get_stream_size(footer_offset: int, file: File) -> int:
    file.seek(footer_offset - BACKWARD_SIZE_LEN, io.SEEK_SET)
    backward_bytes = file.read(BACKWARD_SIZE_LEN)
    stored_backward_size = convert_int32(backward_bytes, Endian.LITTLE)
    real_backward_size = (stored_backward_size + 1) * 4

    if real_backward_size > footer_offset - CRC32_LEN - BACKWARD_SIZE_LEN:
        raise InvalidInputFormat("Invalid backward size.")

    # skip backwards to the end of the Index
    file.seek(-CRC32_LEN - BACKWARD_SIZE_LEN, io.SEEK_CUR)

    # skip backwards of backward size to the start of index
    file.seek(-real_backward_size, io.SEEK_CUR)

    index_size = 0
    index_indicator = convert_int8(file.read(1), Endian.LITTLE)
    # index indicator must be 0, per xz standard
    if index_indicator != 0:
        raise InvalidInputFormat("Invalid index indicator")

    index_size += 1

    # read Index 'Number of Records'
    size, num_records = read_multibyte_int(file)
    index_size += size

    # read Record 'Unpadded Size' and 'Uncompressed Size' for every Record
    blocks_size = 0
    for _ in range(num_records):
        size, unpadded_size = read_multibyte_int(file)
        index_size += size

        size, _ = read_multibyte_int(file)
        index_size += size

        blocks_size += round_up(unpadded_size, XZ_PADDING)

    index_size += CRC32_LEN

    return round_up(
        (STREAM_HEADER_LEN + blocks_size + index_size + STREAM_FOOTER_LEN),
        XZ_PADDING,
    )


def _hyperscan_match(
    context: XZSearchContext, pattern_id: int, offset: int, end: int
) -> Scan:
    del pattern_id, end  # unused arguments
    # if we matched before our start offset, continue looking
    end_offset = offset + FLAG_LEN + EOS_MAGIC_LEN
    if end_offset < context.start_offset:
        return Scan.Continue

    try:
        stream_size = get_stream_size(offset, context.file)
    except InvalidInputFormat:
        return Scan.Continue

    # stream_size does not match, we continue our search
    if stream_size != (end_offset - context.start_offset):
        return Scan.Continue

    # stream padding validation
    # padding MUST contain only null bytes and be 4 bytes aligned
    context.file.seek(end_offset)
    end_padding_offset = read_until_past(context.file, b"\x00")
    padding_size = end_padding_offset - end_offset
    if padding_size % 4 != 0:
        context.end_streams_offset = end_offset
        return Scan.Continue

    # next magic validation
    context.end_streams_offset = end_padding_offset
    context.file.seek(end_padding_offset, io.SEEK_SET)
    magic = context.file.read(len(STREAM_START_MAGIC))
    if magic == STREAM_START_MAGIC:
        context.start_offset = end_padding_offset
        return Scan.Continue
    return Scan.Terminate


class XZHandler(Handler):
    NAME = "xz"

    PATTERNS = [HexString("FD 37 7A 58 5A 00")]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-so", stdout="xz.uncompressed")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset + len(STREAM_START_MAGIC), io.SEEK_SET)
        stream_flag = convert_int16(file.read(2), Endian.BIG)
        if stream_flag not in VALID_FLAGS:
            raise InvalidInputFormat("Invalid stream flag for xz stream.")

        context = XZSearchContext(
            start_offset=start_offset,
            file=file,
            end_streams_offset=-1,
            stream_flag=stream_flag,
        )

        try:
            scanner = hyperscan_stream_end_magic_db.build(context, _hyperscan_match)  # type: ignore
            stream_scan(scanner, file)
        except Exception as e:
            logger.debug(
                "Error scanning for xz patterns",
                error=e,
            )

        if context.end_streams_offset > 0:
            return ValidChunk(
                start_offset=start_offset, end_offset=context.end_streams_offset
            )

        raise InvalidInputFormat("No valid xz compression stream was detected")
