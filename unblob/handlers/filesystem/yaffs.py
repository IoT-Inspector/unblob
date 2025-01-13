import io
import itertools
from collections import defaultdict
from collections.abc import Iterable
from enum import IntEnum
from pathlib import Path
from typing import Optional

import attrs
from structlog import get_logger
from treelib import Tree
from treelib.exceptions import NodeIDAbsentError

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    get_endian_multi,
    read_until_past,
    snull,
)
from unblob.models import Extractor, ExtractResult, Handler, HexString, ValidChunk

logger = get_logger()

SPARE_START_BIG_ENDIAN_ECC = b"\x00\x00\x10\x00"
SPARE_START_BIG_ENDIAN_NO_ECC = b"\xff\xff\x00\x00\x10\x00"
SPARE_START_LITTLE_ENDIAN_ECC = b"\x00\x10\x00\x00"
SPARE_START_LITTLE_ENDIAN_NO_ECC = b"\xff\xff\x00\x10\x00\x00"
SPARE_START_LEN = 6

# YAFFS_OBJECT_TYPE_DIRECTORY, YAFFS_OBJECT_TYPE_FILE
BIG_ENDIAN_MAGICS = [0x00_00_00_01, 0x00_00_00_03]

VALID_PAGE_SIZES = [512, 1024, 2048, 4096, 8192, 16384, 2032]
VALID_SPARE_SIZES = [16, 32, 64, 128, 256, 512]
YAFFS1_PAGE_SIZE = 512
YAFFS1_SPARE_SIZE = 16

C_DEFINITIONS = """
    struct yaffs1_obj_hdr {
        uint32 type;                   /* enum yaffs_obj_type  */
        uint32 parent_obj_id;
        uint16 sum_no_longer_used;
        char name[258];
        uint32 st_mode; // protection
        uint32 st_uid; // user ID of owner
        uint32 st_gid; // group ID of owner
        uint32 st_atime; // time of last access
        uint32 st_mtime; // time of last modification
        uint32 st_ctime; // time of last change
        uint32 file_size; // File size applies to files only
        uint32 equivalent_object_id; // Equivalent object id applies to hard links only.
        char alias[160]; // alias only applies to symlinks
    } yaffs1_obj_hdr_t;

    struct yaffs1_packed_tags {
        uint32 chunk_id:20;
        uint32 serial:2;
        uint32 byte_count:10;
        uint32 object_id:18;
        uint32 ecc:12;
        uint32 unused:2;
    } yaffs1_packed_tags_t;

    typedef struct yaffs_spare
    {
        uint8 tag_b0;
        uint8 tag_b1;
        uint8 tag_b2;
        uint8 tag_b3;
        uint8 page_status; 	// set to 0 to delete the chunk
        uint8 block_status;
        uint8 tag_b4;
        uint8 tag_b5;
        uint8 ecc_0;
        uint8 ecc_1;
        uint8 ecc_2;
        uint8 tag_b6;
        uint8 tag_b7;
        uint8 ecc_3;
        uint8 ecc_4;
        uint8 ecc_5;
    } yaffs_spare_t;

    struct yaffs_file_var {
        uint32 file_size;
        uint32 stored_size;
        uint32 shrink_size;
        int top_level;
    };

    typedef struct yaffs2_obj_hdr {
        uint32 type;                   /* enum yaffs_obj_type  */
        /* Apply to everything  */
        uint32 parent_obj_id;
        uint16 sum_no_longer_used;	    /* checksum of name. No longer used */
        char name[256];
        uint16 chksum;
        /* The following apply to all object types except for hard links */
        uint32 st_mode;		        /* protection */
        uint32 st_uid;
        uint32 st_gid;
        uint32 st_atime;
        uint32 st_mtime;
        uint32 st_ctime;
        uint32 file_size_low;          /* File size  applies to files only */
        int equiv_id;               /* Equivalent object id applies to hard links only. */
        char alias[160];    /* Alias is for symlinks only. */
        uint32 st_rdev;	            /* stuff for block and char devices (major/min) */
        uint32 win_ctime[2];
        uint32 win_atime[2];
        uint32 win_mtime[2];
        uint32 inband_shadowed_obj_id;
        uint32 inband_is_shrink;
        uint32 file_size_high;
        uint32 reserved[1];
        int shadows_obj;	    /* This object header shadows the specified object if > 0 */
        /* is_shrink applies to object headers written when we make a hole. */
        uint32 is_shrink;
        yaffs_file_var filehead;
    } yaffs2_obj_hdr_t;

    typedef struct yaffs2_packed_tags {
        uint32 seq_number;
        uint32 object_id;
        uint32 chunk_id;
        uint32 byte_count;
    }  yaffs2_packed_tags_t;
"""


class YaffsObjectType(IntEnum):
    UNKNOWN = 0
    FILE = 1
    SYMLINK = 2
    DIRECTORY = 3
    HARDLINK = 4
    SPECIAL = 5


@attrs.define
class YAFFSChunk:
    chunk_id: int
    offset: int
    byte_count: int
    object_id: int


@attrs.define
class YAFFS1Chunk(YAFFSChunk):
    serial: int
    ecc: bytes
    page_status: int
    block_status: int


@attrs.define
class YAFFS2Chunk(YAFFSChunk):
    seq_number: int


@attrs.define
class YAFFSFileVar:
    file_size: int
    stored_size: int
    shrink_size: int
    top_level: int


@attrs.define
class YAFFSConfig:
    endianness: Endian
    page_size: int
    spare_size: int
    ecc: bool


@attrs.define
class YAFFSEntry:
    object_type: YaffsObjectType
    object_id: int
    parent_obj_id: int
    sum_no_longer_used: int = attrs.field(default=0)
    name: str = attrs.field(default="")
    alias: str = attrs.field(default="")
    equiv_id: int = attrs.field(default=0)
    file_size: int = attrs.field(default=0)
    st_mode: int = attrs.field(default=0)
    st_uid: int = attrs.field(default=0)
    st_gid: int = attrs.field(default=0)
    st_atime: int = attrs.field(default=0)
    st_mtime: int = attrs.field(default=0)
    st_ctime: int = attrs.field(default=0)

    def __lt__(self, other):
        return self.object_id < other.object_id

    def __gt__(self, other):
        return self.object_id > other.object_id

    def __eq__(self, other):
        return self.object_id == other.object_id

    def __str__(self):
        return f"{self.object_id}: {self.name}"


@attrs.define(kw_only=True)
class YAFFS2Entry(YAFFSEntry):
    chksum: int = attrs.field(default=0)
    st_rdev: int = attrs.field(default=0)
    win_ctime: list[int] = attrs.field(default=[])
    win_mtime: list[int] = attrs.field(default=[])
    inband_shadowed_obj_id: int = attrs.field(default=0)
    inband_is_shrink: int = attrs.field(default=0)
    reserved: list[int] = attrs.field(default=[])
    shadows_obj: int = attrs.field(default=0)
    is_shrink: int = attrs.field(default=0)
    filehead: YAFFSFileVar = attrs.field(default=None)


def iterate_over_file(
    file: File, config: YAFFSConfig
) -> Iterable[tuple[int, bytes, bytes]]:
    start_offset = file.tell()
    page = file.read(config.page_size)
    spare = file.read(config.spare_size)

    while len(page) == config.page_size and len(spare) == config.spare_size:
        yield (start_offset, page, spare)
        page = file.read(config.page_size)
        spare = file.read(config.spare_size)
        start_offset = file.tell()


def decode_file_size(high: int, low: int) -> int:
    """File size can be encoded as 64 bits or 32 bits values.

    If upper 32 bits are set, it's a 64 bits integer value.
    Otherwise it's a 32 bits value. 0xFFFFFFFF means zero.
    """
    if high != 0xFFFFFFFF:
        return (high << 32) | (low & 0xFFFFFFFF)
    if low != 0xFFFFFFFF:
        return low
    return 0


def valid_name(name: bytes) -> bool:
    # a valid name is either full of null bytes, or unicode decodable
    try:
        snull(name[:-1]).decode("utf-8")
    except UnicodeDecodeError:
        return False
    else:
        return True


def is_valid_header(header) -> bool:
    if not valid_name(header.name[:-3]):
        return False
    if header.type > 5:
        return False
    if header.sum_no_longer_used != 0xFFFF:  # noqa: SIM103
        return False
    return True


class YAFFSParser:
    HEADER_STRUCT: str

    def __init__(self, file: File, config: Optional[YAFFSConfig] = None):
        self.file_entries = Tree()
        self.data_chunks = defaultdict(list)
        self.file = file
        self._struct_parser = StructParser(C_DEFINITIONS)
        self.end_offset = -1
        if config is None:
            self.config = self.auto_detect()
            logger.debug("auto-detected config", config=self.config)
        else:
            self.config = config

    def build_entry(self, header, chunk: YAFFSChunk) -> YAFFSEntry:
        raise NotImplementedError

    def build_chunk(self, spare: bytes, offset: int) -> YAFFSChunk:
        raise NotImplementedError

    def get_chunks(self, object_id: int) -> Iterable[YAFFSChunk]:
        raise NotImplementedError

    def init_tree(self):
        return

    def parse(self, store: bool = False):  # noqa: C901,FBT001,FBT002
        self.init_tree()
        entries = 0
        for offset, page, spare in iterate_over_file(self.file, self.config):
            try:
                data_chunk = self.build_chunk(
                    spare, offset - self.config.page_size - self.config.spare_size
                )
            except EOFError:
                break

            # ignore chunks tagged as deleted
            if isinstance(data_chunk, YAFFS1Chunk) and data_chunk.page_status == 0x0:
                continue

            if data_chunk.chunk_id == 0:
                try:
                    header = self._struct_parser.parse(
                        self.HEADER_STRUCT, page, self.config.endianness
                    )
                    logger.debug(self.HEADER_STRUCT, yaffs_obj_hdr=header, _verbosity=3)
                except EOFError:
                    break

                if not is_valid_header(header):
                    break

                if store:
                    self.insert_entry(self.build_entry(header, data_chunk))
                entries += 1
            elif store:
                self.data_chunks[data_chunk.object_id].append(data_chunk)
        if not entries:
            raise InvalidInputFormat("YAFFS filesystem with no entries.")
        self.end_offset = self.file.tell()

    def auto_detect(self) -> YAFFSConfig:
        """Auto-detect page_size, spare_size, and ECC using known signatures."""
        page_size = 0
        config = None
        for page_size in VALID_PAGE_SIZES:
            spare_start = self.file[page_size : page_size + SPARE_START_LEN]
            if spare_start.startswith(SPARE_START_LITTLE_ENDIAN_ECC):
                config = YAFFSConfig(
                    endianness=Endian.LITTLE,
                    page_size=page_size,
                    ecc=True,
                    spare_size=-1,
                )
                break
            if spare_start.startswith(SPARE_START_LITTLE_ENDIAN_NO_ECC):
                config = YAFFSConfig(
                    endianness=Endian.LITTLE,
                    page_size=page_size,
                    ecc=False,
                    spare_size=-1,
                )
                break
            if spare_start.startswith(SPARE_START_BIG_ENDIAN_ECC):
                config = YAFFSConfig(
                    endianness=Endian.BIG, page_size=page_size, ecc=True, spare_size=-1
                )
                break
            if spare_start.startswith(SPARE_START_BIG_ENDIAN_NO_ECC):
                config = YAFFSConfig(
                    endianness=Endian.BIG, page_size=page_size, ecc=False, spare_size=-1
                )
                break

        if config is None:
            raise InvalidInputFormat("Cannot detect YAFFS configuration.")

        # If not using the ECC layout, there are 2 extra bytes at the beginning of the
        # spare data block. Ignore them.

        ecc_offset = 0 if config.ecc else 2

        # The spare data signature is built dynamically, as there are repeating data patterns
        # that we can match on to find where the spare data ends. Take this hexdump for example:
        #
        # 00000800  00 10 00 00 01 01 00 00  00 00 00 00 ff ff ff ff  |................|
        # 00000810  03 00 00 00 01 01 00 00  ff ff 62 61 72 00 00 00  |..........bar...|
        # 00000820  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        #
        # The spare data starts at offset 0x800 and is 16 bytes in size. The next page data then
        # starts at offset 0x810. Not that the four bytes at 0x804 (in the spare data section) and
        # the four bytes at 0x814 (in the next page data section) are identical. This is because
        # the four bytes at offset 0x804 represent the object ID of the previous object, and the four
        # bytes at offset 0x814 represent the parent object ID of the next object. Also, the
        # four bytes in the page data are always followed by 0xFFFF, as those are the unused name
        # checksum bytes.
        #
        # Thus, the signature for identifying the next page section (and hence, the end of the
        # spare data section) becomes: [the 4 bytes starting at offset 0x804] + 0xFFFF
        #
        # Note that this requires at least one non-empty subdirectory; in practice, any Linux
        # file system should meet this requirement, but one could create a file system that
        # does not meet this requirement.

        object_id_offset = 4
        object_id_start = page_size + ecc_offset + object_id_offset
        object_id_end = object_id_start + 4
        spare_signature = self.file[object_id_start:object_id_end] + b"\xff\xff"

        config.spare_size = (
            self.file[object_id_end : object_id_end + page_size].find(spare_signature)
            + object_id_offset
            + ecc_offset
        )

        # Sanity check the spare size, make sure it looks legit
        if config.spare_size not in VALID_SPARE_SIZES:
            raise InvalidInputFormat(
                f"Auto-detection failed: Detected an unlikely spare size: {config.spare_size}"
            )

        return config

    def insert_entry(self, entry: YAFFSEntry):
        duplicate_node = self.get_entry(entry.object_id)
        if duplicate_node is not None:
            # a header chunk with the same object ID already exists
            # in the tree, meaning the file metadata were modified,
            # or the file got truncated / rewritten.
            # Given that YAFFS is a log filesystem, whichever chunk comes
            # last takes precendence.
            self.file_entries.update_node(entry.object_id, data=entry)
            return

        if entry.object_id == entry.parent_obj_id:
            self.file_entries.create_node(
                entry.object_id,
                entry.object_id,
                data=entry,
            )
        else:
            parent_node = self.get_entry(entry.parent_obj_id)
            if parent_node is None:
                logger.warning("Trying to insert an orphaned entry.", entry=entry)
                return
            if parent_node.object_type != YaffsObjectType.DIRECTORY:
                logger.warning(
                    "Trying to insert an entry with non-directory parent.", entry=entry
                )
                return
            self.file_entries.create_node(
                entry.object_id,
                entry.object_id,
                data=entry,
                parent=entry.parent_obj_id,
            )

    def get_entry(self, object_id: int) -> Optional[YAFFSEntry]:
        try:
            entry = self.file_entries.get_node(object_id)
            if entry:
                return entry.data
        except NodeIDAbsentError:
            logger.warning(
                "Can't find entry within the YAFFS tree, something's wrong.",
                object_id=object_id,
            )
        return None

    def resolve_path(self, entry: YAFFSEntry) -> Path:
        resolved_path = Path(entry.name)
        if self.file_entries.parent(entry.object_id) is not None:
            parent_entry = self.file_entries[entry.parent_obj_id].data
            return self.resolve_path(parent_entry).joinpath(resolved_path)
        return resolved_path

    def get_file_chunks(self, entry: YAFFSEntry) -> Iterable[bytes]:
        for chunk in self.get_chunks(entry.object_id):
            yield self.file[chunk.offset : chunk.offset + chunk.byte_count]

    def extract(self, fs: FileSystem):
        for entry in [
            self.file_entries.get_node(node)
            for node in self.file_entries.expand_tree(mode=Tree.DEPTH)
        ]:
            if entry is None or entry.data is None:
                continue
            self.extract_entry(entry.data, fs)

    def extract_entry(self, entry: YAFFSEntry, fs: FileSystem):
        if entry.object_type == YaffsObjectType.UNKNOWN:
            logger.warning("unknown entry type", entry=entry)
            return

        out_path = self.resolve_path(entry)

        if entry.object_type == YaffsObjectType.SPECIAL:
            if not isinstance(entry, YAFFS2Entry):
                logger.warning("non YAFFS2 special object", entry=entry)
                return

            fs.mknod(out_path, entry.st_mode, entry.st_rdev)
        elif entry.object_type == YaffsObjectType.DIRECTORY:
            fs.mkdir(out_path, exist_ok=True)
        elif entry.object_type == YaffsObjectType.FILE:
            fs.write_chunks(out_path, self.get_file_chunks(entry))
        elif entry.object_type == YaffsObjectType.SYMLINK:
            fs.create_symlink(src=Path(entry.alias), dst=out_path)
        elif entry.object_type == YaffsObjectType.HARDLINK:
            dst_entry = self.file_entries[entry.equiv_id].data
            dst_path = self.resolve_path(dst_entry)
            fs.create_hardlink(src=dst_path, dst=out_path)


class YAFFS2Parser(YAFFSParser):
    HEADER_STRUCT = "yaffs2_obj_hdr_t"

    def build_chunk(self, spare: bytes, offset: int) -> YAFFS2Chunk:
        # images built without ECC have two superfluous bytes before the chunk ID.
        if not self.config.ecc:
            # adding two null bytes at the end only works if it's LE
            spare = spare[2:] + b"\x00\x00"

        yaffs2_packed_tags = self._struct_parser.parse(
            "yaffs2_packed_tags_t", spare, self.config.endianness
        )
        logger.debug(
            "yaffs2_packed_tags_t",
            yaffs2_packed_tags=yaffs2_packed_tags,
            config=self.config,
            _verbosity=3,
        )

        return YAFFS2Chunk(
            offset=offset,
            chunk_id=yaffs2_packed_tags.chunk_id,
            seq_number=yaffs2_packed_tags.seq_number,
            byte_count=yaffs2_packed_tags.byte_count,
            object_id=yaffs2_packed_tags.object_id,
        )

    def build_entry(self, header, chunk: YAFFSChunk) -> YAFFSEntry:
        return YAFFS2Entry(
            object_id=chunk.object_id,
            object_type=header.type,
            parent_obj_id=header.parent_obj_id,
            sum_no_longer_used=header.sum_no_longer_used,
            name=snull(header.name[:-1]).decode("utf-8"),
            chksum=header.chksum,
            st_mode=header.st_mode,
            st_uid=header.st_uid,
            st_gid=header.st_gid,
            st_atime=header.st_atime,
            st_mtime=header.st_mtime,
            st_ctime=header.st_ctime,
            equiv_id=header.equiv_id,
            alias=snull(header.alias.replace(b"\xff", b"")).decode("utf-8"),
            st_rdev=header.st_rdev,
            win_ctime=header.win_ctime,
            win_mtime=header.win_mtime,
            inband_shadowed_obj_id=header.inband_shadowed_obj_id,
            inband_is_shrink=header.inband_is_shrink,
            reserved=header.reserved,
            shadows_obj=header.shadows_obj,
            is_shrink=header.is_shrink,
            filehead=YAFFSFileVar(
                file_size=header.filehead.file_size,
                stored_size=header.filehead.stored_size,
                shrink_size=header.filehead.shrink_size,
                top_level=header.filehead.top_level,
            ),
            file_size=decode_file_size(header.file_size_high, header.file_size_low),
        )

    def get_chunks(self, object_id: int) -> Iterable[YAFFS2Chunk]:
        """Return a filtered and ordered list of chunks."""
        # The Yaffs2 sequence number is not the same as the Yaffs1 serial number!

        # As each block is allocated, the file system's
        # sequence number is incremented and each chunk in the block is marked with that
        # sequence number. The sequence number thus provides a way of organising the log in
        # chronological order.

        # Since we're scanning backwards, the most recently written - and thus current - chunk
        # matching an obj_id:chunk_id pair will be encountered first and all subsequent matching chunks must be obsolete and treated as deleted.

        # note: there is no deletion marker in YAFFS2

        for _, chunks in itertools.groupby(
            sorted(self.data_chunks[object_id], key=lambda chunk: chunk.chunk_id)
        ):
            yield max(chunks, key=lambda chunk: chunk.seq_number)

    def init_tree(self):
        # YAFFS2 do not store the root in file.
        root = YAFFS2Entry(
            object_type=YaffsObjectType.DIRECTORY,
            object_id=1,
            parent_obj_id=1,
        )
        self.insert_entry(root)


class YAFFS1Parser(YAFFSParser):
    HEADER_STRUCT = "yaffs1_obj_hdr_t"

    def __init__(self, file: File, config: Optional[YAFFSConfig] = None):
        # from https://yaffs.net/archives/yaffs-development-notes: currently each chunk
        # is the same size as a NAND flash page (ie. 512 bytes + 16 byte spare).
        # In the future we might decide to allow for different chunk sizes.
        config = YAFFSConfig(
            page_size=YAFFS1_PAGE_SIZE,
            spare_size=YAFFS1_SPARE_SIZE,
            endianness=get_endian_multi(file, BIG_ENDIAN_MAGICS),
            ecc=False,
        )
        super().__init__(file, config)

    def build_chunk(self, spare: bytes, offset: int) -> YAFFS1Chunk:
        yaffs_sparse = self._struct_parser.parse(
            "yaffs_spare_t", spare, self.config.endianness
        )

        yaffs_packed_tags = self._struct_parser.parse(
            "yaffs1_packed_tags_t",
            bytes(
                [
                    yaffs_sparse.tag_b0,
                    yaffs_sparse.tag_b1,
                    yaffs_sparse.tag_b2,
                    yaffs_sparse.tag_b3,
                    yaffs_sparse.tag_b4,
                    yaffs_sparse.tag_b5,
                    yaffs_sparse.tag_b6,
                    yaffs_sparse.tag_b7,
                ]
            ),
            self.config.endianness,
        )

        return YAFFS1Chunk(
            offset=offset,
            chunk_id=yaffs_packed_tags.chunk_id,
            serial=yaffs_packed_tags.serial,
            byte_count=yaffs_packed_tags.byte_count,
            object_id=yaffs_packed_tags.object_id,
            ecc=yaffs_packed_tags.ecc,
            page_status=yaffs_sparse.page_status,
            block_status=yaffs_sparse.block_status,
        )

    def build_entry(self, header, chunk: YAFFSChunk) -> YAFFSEntry:
        return YAFFSEntry(
            object_type=header.type,
            object_id=chunk.object_id,
            parent_obj_id=header.parent_obj_id,
            sum_no_longer_used=header.sum_no_longer_used,
            name=snull(header.name[0:128]).decode("utf-8"),
            alias=snull(header.alias.replace(b"\xff", b"")).decode("utf-8"),
            file_size=header.file_size,
            equiv_id=header.equivalent_object_id,
        )

    def get_chunks(self, object_id: int) -> Iterable[YAFFS1Chunk]:
        """Return a filtered and ordered list of chunks."""
        # YAFFS1 chunks have a serial number that is used to track
        # which chunk takes precedence if two chunks have the same
        # identifier. This is used in scenarios like power loss
        # during a copy operation. Whenever we have two chunks with
        # the same id, we only return the one with the highest serial.

        for _, chunks in itertools.groupby(
            sorted(
                self.data_chunks[object_id],
                key=lambda chunk: chunk.chunk_id,
            )
        ):
            # serial is a 2 bit, this function works since there's always at most
            # two chunks with the same chunk_id at any given time
            yield max(chunks, key=lambda chunk: ((chunk.serial + 1) & 3))


def is_yaffs_v1(file: File, start_offset: int) -> bool:
    struct_parser = StructParser(C_DEFINITIONS)
    file.seek(start_offset, io.SEEK_SET)
    if file[0:4] == b"\x03\x00\x00\x00" or file[0:4] == b"\x01\x00\x00\x00":
        endian = Endian.LITTLE
    else:
        endian = Endian.BIG
    file.seek(start_offset + YAFFS1_PAGE_SIZE, io.SEEK_SET)
    spare = file.read(YAFFS1_SPARE_SIZE)

    yaffs_sparse = struct_parser.parse("yaffs_spare_t", spare, endian)

    yaffs_packed_tags = struct_parser.parse(
        "yaffs1_packed_tags_t",
        bytes(
            [
                yaffs_sparse.tag_b0,
                yaffs_sparse.tag_b1,
                yaffs_sparse.tag_b2,
                yaffs_sparse.tag_b3,
                yaffs_sparse.tag_b4,
                yaffs_sparse.tag_b5,
                yaffs_sparse.tag_b6,
                yaffs_sparse.tag_b7,
            ]
        ),
        endian,
    )
    file.seek(start_offset, io.SEEK_SET)
    return (
        yaffs_packed_tags.chunk_id == 0
        and yaffs_packed_tags.serial == 0
        and yaffs_packed_tags.object_id == 1
    )


def instantiate_parser(file: File, start_offset: int = 0) -> YAFFSParser:
    if is_yaffs_v1(file, start_offset):
        return YAFFS1Parser(file)
    return YAFFS2Parser(file)


class YAFFSExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        infile = File.from_path(inpath)
        parser = instantiate_parser(infile)
        parser.parse(store=True)
        fs = FileSystem(outdir)
        parser.extract(fs)
        return ExtractResult(reports=fs.problems)


class YAFFSHandler(Handler):
    NAME = "yaffs"

    PATTERNS = [
        HexString(
            "03 00 00 00 01 00 00 00 ff ff // YAFFS_OBJECT_TYPE_DIRECTORY in little endian"
        ),
        HexString(
            "01 00 00 00 01 00 00 00 ff ff // YAFFS_OBJECT_TYPE_FILE in little endian"
        ),
        HexString(
            "00 00 00 03 00 00 00 01 ff ff // YAFFS_OBJECT_TYPE_DIRECTORY in big endian"
        ),
        HexString(
            "00 00 00 01 00 00 00 01 ff ff // YAFFS_OBJECT_TYPE_FILE in big endian"
        ),
    ]

    EXTRACTOR = YAFFSExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        parser = instantiate_parser(file, start_offset)
        parser.parse()
        # skip 0xFF padding
        file.seek(parser.end_offset, io.SEEK_SET)
        read_until_past(file, b"\xff")
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())
