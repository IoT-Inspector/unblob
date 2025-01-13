import io
import os
import stat
from pathlib import Path
from typing import Optional

import attrs
from structlog import get_logger

from ...file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    decode_int,
    iterate_file,
    round_up,
    snull,
)
from ...models import (
    Extractor,
    ExtractResult,
    File,
    Handler,
    HexString,
    ValidChunk,
)

logger = get_logger()

CPIO_TRAILER_NAME = "TRAILER!!!"
MAX_LINUX_PATH_LENGTH = 0x1000

C_ISBLK = 0o60000
C_ISCHR = 0o20000
C_ISDIR = 0o40000
C_ISFIFO = 0o10000
C_ISSOCK = 0o140000
C_ISLNK = 0o120000
C_ISCTG = 0o110000
C_ISREG = 0o100000

C_FILE_TYPES = (
    C_ISBLK,
    C_ISCHR,
    C_ISDIR,
    C_ISFIFO,
    C_ISSOCK,
    C_ISLNK,
    C_ISCTG,
    C_ISREG,
)

C_NONE = 0o00000
C_ISUID = 0o04000
C_ISGID = 0o02000
C_ISVTX = 0o01000
C_ISUID_ISGID = 0o06000

C_STICKY_BITS = (C_NONE, C_ISUID, C_ISGID, C_ISVTX, C_ISUID_ISGID)

C_DEFINITIONS = r"""
    typedef struct old_cpio_header
    {
        uint16 c_magic;
        uint16 c_dev;
        uint16 c_ino;
        uint16 c_mode;
        uint16 c_uid;
        uint16 c_gid;
        uint16 c_nlink;
        uint16 c_rdev;
        uint16 c_mtimes[2];
        uint16 c_namesize;
        uint16 c_filesize[2];
    } old_cpio_header_t;

    typedef struct old_ascii_header
    {
        char c_magic[6];
        char c_dev[6];
        char c_ino[6];
        char c_mode[6];
        char c_uid[6];
        char c_gid[6];
        char c_nlink[6];
        char c_rdev[6];
        char c_mtime[11];
        char c_namesize[6];
        char c_filesize[11];
    } old_ascii_header_t;

    typedef struct new_ascii_header
    {
        char c_magic[6];
        char c_ino[8];
        char c_mode[8];
        char c_uid[8];
        char c_gid[8];
        char c_nlink[8];
        char c_mtime[8];
        char c_filesize[8];
        char c_dev_maj[8];
        char c_dev_min[8];
        char c_rdev_maj[8];
        char c_rdev_min[8];
        char c_namesize[8];
        char c_chksum[8];
    } new_ascii_header_t;
"""


@attrs.define
class CPIOEntry:
    start_offset: int
    size: int
    dev: int
    mode: int
    rdev: int
    path: Path


class CPIOParserBase:
    _PAD_ALIGN: int
    _FILE_PAD_ALIGN: int = 512
    HEADER_STRUCT: str

    def __init__(self, file: File, start_offset: int):
        self.file = file
        self.start_offset = start_offset
        self.end_offset = -1
        self.entries = []
        self.struct_parser = StructParser(C_DEFINITIONS)

    def parse(self):  # noqa: C901
        current_offset = self.start_offset
        while True:
            self.file.seek(current_offset, io.SEEK_SET)
            try:
                header = self.struct_parser.parse(
                    self.HEADER_STRUCT, self.file, Endian.LITTLE
                )
            except EOFError:
                break

            c_filesize = self._calculate_file_size(header)
            c_namesize = self._calculate_name_size(header)

            # heuristics 1: check the filename
            if c_namesize > MAX_LINUX_PATH_LENGTH:
                raise InvalidInputFormat("CPIO entry filename is too long.")

            if c_namesize == 0:
                raise InvalidInputFormat("CPIO entry filename empty.")

            padded_header_size = self._pad_header(header, c_namesize)
            current_offset += padded_header_size

            tmp_filename = self.file.read(c_namesize)

            # heuristics 2: check that filename is null-byte terminated
            if not tmp_filename.endswith(b"\x00"):
                raise InvalidInputFormat(
                    "CPIO entry filename is not null-byte terminated"
                )

            try:
                filename = snull(tmp_filename).decode("utf-8")
            except UnicodeDecodeError as e:
                raise InvalidInputFormat from e

            if filename == CPIO_TRAILER_NAME:
                current_offset += self._pad_content(c_filesize)
                break

            c_mode = self._calculate_mode(header)

            file_type = c_mode & 0o770000
            sticky_bit = c_mode & 0o7000

            # heuristics 3: check mode field
            is_valid = file_type in C_FILE_TYPES and sticky_bit in C_STICKY_BITS
            if not is_valid:
                raise InvalidInputFormat("CPIO entry mode is invalid.")

            if self.valid_checksum(header, current_offset):
                self.entries.append(
                    CPIOEntry(
                        start_offset=current_offset,
                        size=c_filesize,
                        dev=self._calculate_dev(header),
                        mode=c_mode,
                        rdev=self._calculate_rdev(header),
                        path=Path(filename),
                    )
                )
            else:
                logger.warning("Invalid CRC for CPIO entry, skipping.", header=header)

            current_offset += self._pad_content(c_filesize)

        self.end_offset = self._pad_file(current_offset)
        if self.start_offset == self.end_offset:
            raise InvalidInputFormat("Invalid CPIO archive.")

    def dump_entries(self, fs: FileSystem):
        for entry in self.entries:
            # skip entries with "." as filename
            if entry.path.name in ("", "."):
                continue

            # There are cases where CPIO archives have duplicated entries
            # We then unlink the files to overwrite them and avoid an error.
            if not stat.S_ISDIR(entry.mode):
                fs.unlink(entry.path)

            if stat.S_ISREG(entry.mode):
                fs.carve(entry.path, self.file, entry.start_offset, entry.size)
            elif stat.S_ISDIR(entry.mode):
                fs.mkdir(
                    entry.path, mode=entry.mode & 0o777, parents=True, exist_ok=True
                )
            elif stat.S_ISLNK(entry.mode):
                link_path = Path(
                    snull(
                        self.file[entry.start_offset : entry.start_offset + entry.size]
                    ).decode("utf-8")
                )
                fs.create_symlink(src=link_path, dst=entry.path)
            elif (
                stat.S_ISCHR(entry.mode)
                or stat.S_ISBLK(entry.mode)
                or stat.S_ISSOCK(entry.mode)
                or stat.S_ISSOCK(entry.mode)
            ):
                fs.mknod(entry.path, mode=entry.mode & 0o777, device=entry.rdev)
            else:
                logger.warning("unknown file type in CPIO archive")

    def _pad_file(self, end_offset: int) -> int:
        """CPIO archives can have a 512 bytes block padding at the end."""
        self.file.seek(end_offset, io.SEEK_SET)
        padded_end_offset = self.start_offset + round_up(
            size=end_offset - self.start_offset, alignment=self._FILE_PAD_ALIGN
        )
        padding_size = padded_end_offset - end_offset

        if self.file.read(padding_size) == bytes([0]) * padding_size:
            return padded_end_offset

        return end_offset

    @classmethod
    def _pad_header(cls, header, c_namesize: int) -> int:
        return round_up(len(header) + c_namesize, cls._PAD_ALIGN)

    @classmethod
    def _pad_content(cls, c_filesize: int) -> int:
        """Pad header and content with _PAD_ALIGN bytes."""
        return round_up(c_filesize, cls._PAD_ALIGN)

    @staticmethod
    def _calculate_file_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_name_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_mode(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_dev(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_rdev(header) -> int:
        raise NotImplementedError

    def valid_checksum(self, header, start_offset: int) -> bool:  # noqa: ARG002
        return True


class BinaryCPIOParser(CPIOParserBase):
    _PAD_ALIGN = 2

    HEADER_STRUCT = "old_cpio_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return header.c_filesize[0] << 16 | header.c_filesize[1]

    @staticmethod
    def _calculate_name_size(header) -> int:
        return header.c_namesize + 1 if header.c_namesize % 2 else header.c_namesize

    @staticmethod
    def _calculate_mode(header) -> int:
        return header.c_mode

    @staticmethod
    def _calculate_dev(header) -> int:
        return header.c_dev

    @staticmethod
    def _calculate_rdev(header) -> int:
        return header.c_rdev


class PortableOldASCIIParser(CPIOParserBase):
    _PAD_ALIGN = 1

    HEADER_STRUCT = "old_ascii_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 8)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 8)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 8)

    @staticmethod
    def _calculate_dev(header) -> int:
        return decode_int(header.c_dev, 8)

    @staticmethod
    def _calculate_rdev(header) -> int:
        return decode_int(header.c_rdev, 8)


class PortableASCIIParser(CPIOParserBase):
    _PAD_ALIGN = 4
    HEADER_STRUCT = "new_ascii_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 16)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 16)

    @staticmethod
    def _calculate_dev(header) -> int:
        return os.makedev(
            decode_int(header.c_dev_maj, 16), decode_int(header.c_dev_min, 16)
        )

    @staticmethod
    def _calculate_rdev(header) -> int:
        return os.makedev(
            decode_int(header.c_rdev_maj, 16), decode_int(header.c_rdev_min, 16)
        )


class PortableASCIIWithCRCParser(PortableASCIIParser):
    def valid_checksum(self, header, start_offset: int) -> bool:
        header_checksum = decode_int(header.c_chksum, 16)
        calculated_checksum = 0
        file_size = self._calculate_file_size(header)

        for chunk in iterate_file(self.file, start_offset, file_size):
            calculated_checksum += sum(bytearray(chunk))
        return header_checksum == calculated_checksum & 0xFF_FF_FF_FF


class _CPIOExtractorBase(Extractor):
    PARSER: type[CPIOParserBase]

    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        fs = FileSystem(outdir)

        with File.from_path(inpath) as file:
            parser = self.PARSER(file, 0)
            parser.parse()
            parser.dump_entries(fs)


class BinaryCPIOExtractor(_CPIOExtractorBase):
    PARSER = BinaryCPIOParser


class PortableOldASCIIExtractor(_CPIOExtractorBase):
    PARSER = PortableOldASCIIParser


class PortableASCIIExtractor(_CPIOExtractorBase):
    PARSER = PortableASCIIParser


class PortableASCIIWithCRCExtractor(_CPIOExtractorBase):
    PARSER = PortableASCIIWithCRCParser


class _CPIOHandlerBase(Handler):
    """A common base for all CPIO formats.

    The format should be parsed the same, there are small differences how to calculate
    file and filename sizes padding and conversion from octal / hex.
    """

    EXTRACTOR: _CPIOExtractorBase

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        parser = self.EXTRACTOR.PARSER(file, start_offset)
        parser.parse()
        return ValidChunk(
            start_offset=start_offset,
            end_offset=parser.end_offset,
        )


class BinaryHandler(_CPIOHandlerBase):
    NAME = "cpio_binary"
    PATTERNS = [HexString("c7 71 // (default, bin, hpbin)")]

    EXTRACTOR = BinaryCPIOExtractor()


class PortableOldASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_old_ascii"

    PATTERNS = [HexString("30 37 30 37 30 37 // 07 07 07")]

    EXTRACTOR = PortableOldASCIIExtractor()


class PortableASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_ascii"
    PATTERNS = [HexString("30 37 30 37 30 31 // 07 07 01 (newc)")]

    EXTRACTOR = PortableASCIIExtractor()


class PortableASCIIWithCRCHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_ascii_crc"
    PATTERNS = [HexString("30 37 30 37 30 32 // 07 07 02")]

    EXTRACTOR = PortableASCIIWithCRCExtractor()
