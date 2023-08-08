from pathlib import Path
from typing import List, Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, StructParser, get_endian, round_up
from ...models import Extractor, File, HexString, StructHandler, ValidChunk

logger = get_logger()

PAD_SIZES = [4_096, 1_024]


class SquashFSExtractor(Extractor):
    EXECUTABLE = "sasquatch"

    def __init__(self, big_endian_magic: int):
        self.big_endian_magic = big_endian_magic

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            endian = get_endian(file, self.big_endian_magic)

        commands_args = []

        if endian == Endian.BIG:
            commands_args.append("-be")
        else:
            commands_args.append("-le")

        commands_args.extend(
            [
                "-no-exit-code",
                "-f",
                "-d",
                "{outdir}",
                "{inpath}",
            ]
        )
        extractor = Command(self.EXECUTABLE, *commands_args)
        extractor.extract(inpath, outdir)

    def get_dependencies(self) -> List[str]:
        return [self.EXECUTABLE]


class _SquashFSBase(StructHandler):
    BIG_ENDIAN_MAGIC = 0x73_71_73_68

    EXTRACTOR = SquashFSExtractor(0x73_71_73_68)

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset)
        endian = get_endian(file, self.BIG_ENDIAN_MAGIC)
        header = self.parse_header(file, endian)

        end_of_data_offset = start_offset + header.bytes_used
        file.seek(end_of_data_offset)
        padding = file.read(
            round_up(header.bytes_used, max(PAD_SIZES)) - header.bytes_used
        )

        for pad_size in sorted(PAD_SIZES, reverse=True):
            size = round_up(header.bytes_used, pad_size)
            padding_length = size - header.bytes_used

            if padding.startswith(b"\00" * padding_length):
                end_offset = start_offset + size
                return ValidChunk(start_offset=start_offset, end_offset=end_offset)

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + header.bytes_used
        )


class SquashFSv2Handler(_SquashFSBase):
    NAME = "squashfs_v2"

    PATTERNS = [
        HexString(
            """
            // 00000000  73 71 73 68 00 00 00 03  00 00 00 00 00 00 00 00  |sqsh............|
            // 00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 02 00 00  |................|
            // squashfs_v2_magic_be
            73 71 73 68 [24] 00 02
        """
        ),
        HexString(
            """
            // 00000000  68 73 71 73 03 00 00 00  00 00 00 00 00 00 00 00  |hsqs............|
            // 00000010  00 00 00 00 00 00 00 00  00 00 00 00 02 00 00 00  |................|
            // squashfs_v2_magic_le
            68 73 71 73 [24] 02 00
        """
        ),
    ]

    C_DEFINITIONS = r"""
        typedef struct squashfs2_super_block
        {
            char   s_magic[4];
            uint32 inodes;
            uint32 bytes_used;
            uint32 uid_start;
            uint32 guid_start;
            uint32 inode_table_start;
            uint32 directory_table_start;
            uint16 s_major;
            uint16 s_minor;
        } squashfs2_super_block_t;
    """
    HEADER_STRUCT = "squashfs2_super_block_t"


class SquashFSv2NonStandardHandler(SquashFSv2Handler):
    NAME = "squashfs_v2_nonstandard"

    BIG_ENDIAN_MAGIC = 0x73_71_6C_7A

    EXTRACTOR = SquashFSExtractor(0x73_71_6C_7A)

    PATTERNS = [
        HexString(
            """
            // 00000000  73 71 6c 7a 00 00 03 3f  00 21 99 d7 00 21 99 c7  |sqlz...?........|
            // 00000010  00 00 00 00 00 21 71 7c  00 21 82 89 00 02 00 01  |.!...!.......!q.|
            // squashfs_v2_magic_non_standard_be
            73 71 6c 7a [24] 00 02
        """
        ),
    ]


class SquashFSv3Handler(_SquashFSBase):
    NAME = "squashfs_v3"

    PATTERNS = [
        HexString(
            """
            // 00000000  73 71 73 68 00 00 00 03  00 00 00 00 00 00 00 00  |sqsh............|
            // 00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 03 00 00  |................|
            // squashfs_v3_magic_be
            73 71 73 68 [24] 00 03
        """
        ),
        HexString(
            """
            // 00000000  68 73 71 73 03 00 00 00  00 00 00 00 00 00 00 00  |hsqs............|
            // 00000010  00 00 00 00 00 00 00 00  00 00 00 00 03 00 00 00  |................|
            // squashfs_v3_magic_le
            68 73 71 73 [24] 03 00
        """
        ),
    ]

    C_DEFINITIONS = r"""
        typedef struct squashfs3_super_block
        {
            char   s_magic[4];
            uint32 inodes;
            uint32 bytes_used_2;
            uint32 uid_start_2;
            uint32 guid_start_2;
            uint32 inode_table_start_2;
            uint32 directory_table_start_2;
            uint16 s_major;
            uint16 s_minor;
            uint16 block_size_1;
            uint16 block_log;
            uint8  flags;
            uint8  no_uids;
            uint8  no_guids;
            uint32 mkfs_time /* time of filesystem creation */;
            uint64 root_inode;
            uint32 block_size;
            uint32 fragments;
            uint32 fragment_table_start_2;
            uint64  bytes_used;
            uint64  uid_start;
            uint64  guid_start;
            uint64  inode_table_start;
            uint64  directory_table_start;
            uint64  fragment_table_start;
            uint64  lookup_table_start;
        } squashfs3_super_block_t;
    """
    HEADER_STRUCT = "squashfs3_super_block_t"


class SquashFSv3DDWRTHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_ddwrt"

    BIG_ENDIAN_MAGIC = 0x74_71_73_68

    EXTRACTOR = SquashFSExtractor(0x74_71_73_68)

    PATTERNS = [
        HexString(
            """
            // 00000000  68 73 71 74 21 02 00 00  00 00 00 00 00 00 00 00  |hsqt!...........|
            // 00000010  00 00 00 00 00 00 00 00  50 02 00 00 03 00 00 00  |........P.......|
            // squashfs_v3_magic_ddwrt_le
            68 73 71 74 [24] 03 00
        """
        ),
        HexString(
            """
            // 00000000  74 71 73 68 00 00 00 05  00 00 00 00 00 00 00 00  |tqsh............|
            // 00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 03 00 01  |................|
            // squashfs_v3_magic_ddwrt_be
            74 71 73 68 [24] 00 03
        """
        ),
    ]


class SquashFSv3BroadcomHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_broadcom"

    BIG_ENDIAN_MAGIC = 0x71_73_68_73

    EXTRACTOR = SquashFSExtractor(0x71_73_68_73)

    PATTERNS = [
        HexString(
            """
            // 00000000  73 68 73 71 0f 05 00 00  c8 a9 00 01 00 00 00 bc  |shsq............|
            // 00000010  1f 2d 00 a2 d0 2b 00 bf  79 2e 00 65 03 00 00 00  |.-...+..y..e....|
            // squashfs_v3_magic_broadcom_le
            73 68 73 71 [24] 03 00
        """
        ),
        HexString(
            """
            // 00000000  71 73 68 73 0f 05 00 00  c8 a9 00 01 00 00 00 bc  |qshs............|
            // 00000010  1f 2d 00 a2 d0 2b 00 bf  79 2e 00 65 00 03 00 00  |.-...+..y..e....|
            // squashfs_v3_magic_broadcom_be
            71 73 68 73 [24] 00 03

        """
        ),
    ]


class SquashFSv3NSHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_nonstandard"

    BIG_ENDIAN_MAGIC = 0x73_71_6C_7A

    EXTRACTOR = SquashFSExtractor(0x73_71_6C_7A)

    PATTERNS = [
        HexString(
            """
            // 00000000  7a 6c 71 73 00 00 04 df  57 00 17 95 46 00 19 ed  |zlqs....W...F...|
            // 00000010  20 08 04 8e 02 40 01 06  c9 02 16 00 00 03 00 01  | ....@..........|
            // squashfs_v3_magic_nonstandard_le
            7A 6c 71 73 [24] 03 00
        """
        ),
        HexString(
            """
            // 00000000  73 71 6c 7a 00 00 04 df  57 00 17 95 46 00 19 ed  |sqlz....W...F...|
            // 00000010  20 08 04 8e 02 40 01 06  c9 02 16 00 00 03 00 01  | ....@..........|
            // squashfs_v3_magic_nonstandard_be
            73 71 6c 7A [24] 00 03
        """
        ),
    ]


class SquashFSv4LEHandler(_SquashFSBase):
    NAME = "squashfs_v4_le"

    PATTERNS = [
        HexString(
            """
            // 00000000  68 73 71 73 03 00 00 00  00 c1 9c 61 00 00 02 00  |hsqs.......a....|
            // 00000010  01 00 00 00 01 00 11 00  c0 00 01 00 04 00 00 00  |................|
            // squashfs_v4_magic_le
            68 73 71 73 [24] 04 00
        """
        ),
    ]

    C_DEFINITIONS = r"""
        typedef struct squashfs4_super_block
        {
            char   s_magic[4];
            uint32 inodes;
            uint32 mkfs_time /* time of filesystem creation */;
            uint32 block_size;
            uint32 fragments;
            uint16 compression;
            uint16 block_log;
            uint16  flags;
            uint16  no_ids;
            uint16 s_major;
            uint16 s_minor;
            uint64 root_inode;
            uint64  bytes_used;
            uint64  id_table_start;
            uint64  xattr_id_table_start;
            uint64  inode_table_start;
            uint64  directory_table_start;
            uint64  fragment_table_start;
            uint64  lookup_table_start;
        } squashfs4_super_block_t;
    """
    HEADER_STRUCT = "squashfs4_super_block_t"


class SquashFSv4BEExtractor(Extractor):
    EXECUTABLE = "sasquatch-v4be"

    def is_avm(self, header: Instance) -> bool:
        # see https://raw.githubusercontent.com/Freetz/freetz/master/tools/make/squashfs4-host-be/AVM-BE-format.txt
        return header.bytes_used == header.mkfs_time

    def extract(self, inpath: Path, outdir: Path):
        struct_parser = StructParser(SquashFSv4LEHandler.C_DEFINITIONS)

        with File.from_path(inpath) as f:
            header = struct_parser.parse(
                SquashFSv4LEHandler.HEADER_STRUCT, f, Endian.BIG
            )

        commands_args = []

        if not self.is_avm(header):
            commands_args.append("-be")

        commands_args.extend(
            [
                "-no-exit-code",
                "-f",
                "-d",
                "{outdir}",
                "{inpath}",
            ]
        )
        extractor = Command(self.EXECUTABLE, *commands_args)
        extractor.extract(inpath, outdir)

    def get_dependencies(self) -> List[str]:
        return [self.EXECUTABLE]


class SquashFSv4BEHandler(SquashFSv4LEHandler):
    NAME = "squashfs_v4_be"

    PATTERNS = [
        HexString(
            """
            // 00000000  73 71 73 68 03 00 00 00  00 c1 9c 61 00 00 02 00  |sqsh.......a....|
            // 00000010  01 00 00 00 01 00 11 00  c0 00 01 00 04 00 00 00  |................|
            // squashfs_v4_magic_be
            73 71 73 68 [24] 00 04
        """
        )
    ]

    EXTRACTOR = SquashFSv4BEExtractor()
