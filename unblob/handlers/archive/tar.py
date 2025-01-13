import contextlib
import os
import tarfile
from pathlib import Path
from typing import Optional

from structlog import get_logger

from ...file_utils import OffsetFile, SeekError, decode_int, round_up, snull
from ...models import (
    Extractor,
    ExtractResult,
    File,
    HexString,
    Regex,
    StructHandler,
    ValidChunk,
)
from ._safe_tarfile import SafeTarFile

logger = get_logger()


BLOCK_SIZE = 512
END_OF_ARCHIVE_MARKER_SIZE = 2 * BLOCK_SIZE

MAGIC_OFFSET = 257

ZERO_BLOCK = bytes([0]) * BLOCK_SIZE


def _get_tar_end_offset(file: File, offset=0):
    file_with_offset = OffsetFile(file, offset)

    # First find the end of the last entry in the file
    last_offset = _get_end_of_last_tar_entry(file_with_offset)
    if last_offset == -1:
        return -1

    # Then find where the final zero blocks end
    return offset + _find_end_of_padding(file_with_offset, find_from=last_offset)


def _get_end_of_last_tar_entry(file) -> int:
    try:
        tf = tarfile.TarFile(mode="r", fileobj=file)
    except tarfile.TarError:
        return -1

    last_member = None

    try:
        for member in tf:
            last_member = member
    except (tarfile.TarError, SeekError):
        # recover what's already been parsed
        pass

    if last_member is None:
        return -1

    end_of_last_tar_entry = tf.offset
    try:
        file.seek(end_of_last_tar_entry)
    except SeekError:
        # last tar entry is truncated
        end_of_last_tar_entry = last_member.offset
        file.seek(end_of_last_tar_entry)

    return end_of_last_tar_entry


def _find_end_of_padding(file, *, find_from: int) -> int:
    find_from = round_up(find_from, BLOCK_SIZE)
    find_to = round_up(find_from + END_OF_ARCHIVE_MARKER_SIZE, tarfile.RECORDSIZE)

    max_padding_blocks = (find_to - find_from) // BLOCK_SIZE

    try:
        file.seek(find_from)
    except SeekError:
        # match to end of truncated file
        return file.seek(0, os.SEEK_END)

    for padding_blocks in range(max_padding_blocks):  # noqa: B007
        if file.read(BLOCK_SIZE) != ZERO_BLOCK:
            break
    else:
        padding_blocks = max_padding_blocks

    return find_from + padding_blocks * BLOCK_SIZE


class TarExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        with contextlib.closing(SafeTarFile(inpath)) as tarfile:
            tarfile.extractall(outdir)  # noqa: S202 tarfile-unsafe-members
        return ExtractResult(reports=tarfile.reports)


class _TarHandler(StructHandler):
    NAME = "tar"

    PATTERNS = []

    C_DEFINITIONS = r"""
        typedef struct posix_header
        {                       /* byte offset */
            char name[100];     /*   0 */
            char mode[8];       /* 100 */
            char uid[8];        /* 108 */
            char gid[8];        /* 116 */
            char size[12];      /* 124 */
            char mtime[12];     /* 136 */
            char chksum[8];     /* 148 */
            char typeflag;      /* 156 */
            char linkname[100]; /* 157 */
            char magic[6];      /* 257 */
            char version[2];    /* 263 */
            char uname[32];     /* 265 */
            char gname[32];     /* 297 */
            char devmajor[8];   /* 329 */
            char devminor[8];   /* 337 */
            char prefix[155];   /* 345 */
                                /* 500 */
        } posix_header_t;
    """
    HEADER_STRUCT = "posix_header_t"

    EXTRACTOR = TarExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset)
        header = self.parse_header(file)
        header_size = snull(header.size)
        decode_int(header_size, 8)

        def signed_sum(octets) -> int:
            return sum(b if b < 128 else 256 - b for b in octets)

        if header.chksum[6:8] not in (b"\x00 ", b" \x00"):
            logger.debug(
                "Invalid checksum format",
                actual_last_2_bytes=header.chksum[6:8],
                handler=self.NAME,
                _verbosity=3,
            )
            return None
        checksum = decode_int(header.chksum[:6], 8)
        header_bytes_for_checksum = (
            file[start_offset : start_offset + 148]
            + b" " * 8  # chksum field is replaced with "blanks"
            + file[start_offset + 156 : start_offset + 257]
        )
        extended_header_bytes = file[start_offset + 257 : start_offset + 500]
        calculated_checksum_unsigned = sum(header_bytes_for_checksum)
        calculated_checksum_signed = signed_sum(header_bytes_for_checksum)
        checksums = (
            calculated_checksum_unsigned,
            calculated_checksum_unsigned + sum(extended_header_bytes),
            # signed is of historical interest, calculating for the extended header is not needed
            calculated_checksum_signed,
        )
        if checksum not in checksums:
            logger.error(
                "Tar header checksum mismatch", expected=str(checksum), actual=checksums
            )
            return None

        end_offset = _get_tar_end_offset(file, start_offset)
        if end_offset == -1:
            return None
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)


class TarUstarHandler(_TarHandler):
    PATTERNS = [
        HexString("75 73 74 61 72 20 20 00"),
        HexString("75 73 74 61 72 00 30 30"),
    ]

    # Since the magic is at 257, we have to subtract that from the match offset
    # to get to the start of the file.
    PATTERN_MATCH_OFFSET = -MAGIC_OFFSET


def _re_frame(regexp: str):
    """Wrap regexp to ensure its integrity from concatenation.

    E.g.: when the regex
      a|b
    is naively appended by regex c, the result
      a|bc
    will not match "ac", while
      (a|b)c
    will match "ac" as intended.
    """
    return f"({regexp})"


def _re_alternatives(regexps):
    return _re_frame("|".join(_re_frame(regexp) for regexp in regexps))


def _padded_field(re_content_char, size, leftpad_re=" ", rightpad_re=r"[ \0x00]"):
    field_regexes = []

    for padsize in range(size):
        content_re = f"{re_content_char}{{{size - padsize}}}"

        for leftpadsize in range(padsize + 1):
            rightpadsize = padsize - leftpadsize

            left_re = f"{leftpad_re}{{{leftpadsize}}}" if leftpadsize else ""
            right_re = f"{rightpad_re}{{{rightpadsize}}}" if rightpadsize else ""

            field_regexes.append(f"{left_re}{content_re}{right_re}")

    return _re_alternatives(field_regexes)


class TarUnixHandler(_TarHandler):
    PATTERNS = [
        Regex(
            r""
            #  (pattern would be too big)   char name[100]
            + _padded_field(r"[0-7]", 8)  # char mode[8]
            + _padded_field(r"[0-7]", 8)  # char uid[8]
            + _padded_field(r"[0-7]", 8)  # char gid[8]
            + _padded_field(r"[0-7]", 12)  # char size[12]
            + _padded_field(r"[0-7]", 12)  # char mtime[12]
            + _padded_field(r"[0-7]", 8)  # char chksum[8]
            + r"[0-7\x00]"  # char typeflag[1] - no extensions
            # Extending/dropping typeflag pattern would cover all tar formats,
            # r"[0-7xgA-Z\x00]" would probably match all current major implementations.
            # Info on the values for typeflag:
            #  - https://en.wikipedia.org/wiki/Tar_(computing)
            #  - https://www.gnu.org/software/tar/manual/html_node/Standard.html
            #  - https://github.com/openbsd/src/blob/master/bin/pax/tar.h
            #  - https://codebrowser.dev/glibc/glibc/posix/tar.h.html
            #  - https://www.ibm.com/docs/el/aix/7.2?topic=files-tarh-file
            # Values 'A'-'Z' are reserved for custom implementations.
            # All other values are reserved for future POSIX.1 revisions.
            # Several places mention custom extensions and how they extract it,
            # e.g. the IBM link above is quite explicit.
            # Since its possible values are somewhat vague,
            # it might be better still to not include this field in the pattern at all.
        ),
    ]
    PATTERN_MATCH_OFFSET = -100  # go back to beginning of skipped name
