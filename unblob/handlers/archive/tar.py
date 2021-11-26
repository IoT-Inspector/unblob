import io
import tarfile
from typing import List, Optional

from structlog import get_logger

from ...file_utils import snull
from ...models import StructHandler, ValidChunk

logger = get_logger()


BLOCK_SIZE = HEADER_SIZE = 512

# Because the header of the tar file doesn't necessarily
# contain the size of the whole tar block (because "Physically,
# an archive consists of a series of file entries terminated
# by an end-of-archive entry, which consists of two 512 blocks
# of zero bytes.") - we need to parse the concurrent tar chunks,
# and then return the size of the total file once we reach the
# blocks of NULLs.
# https://www.gnu.org/software/tar/manual/html_node/Standard.html
END_BLOCK_SIZE = BLOCK_SIZE * 2
END_BLOCK = b"\x00" * END_BLOCK_SIZE

MAGIC_OFFSET = 257


def _get_tar_end_offset(file: io.BufferedIOBase):
    tf = tarfile.TarFile(mode="r", fileobj=file)
    last_member = tf.getmembers()[-1]
    last_file_size = BLOCK_SIZE * (1 + (last_member.size // BLOCK_SIZE))
    end_offset = last_member.offset + HEADER_SIZE + last_file_size + END_BLOCK_SIZE
    return end_offset


class TarHandler(StructHandler):
    NAME = "tar"

    YARA_RULE = r"""
        strings:
            $tar_magic = { 75 73 74 61 72 }

        condition:
            $tar_magic
    """

    # Since the magic is at 257, we have to subtract that from the match offset
    # to get to the start of the file.
    YARA_MATCH_OFFSET = -MAGIC_OFFSET

    C_DEFINITIONS = r"""
        struct posix_header
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
        };
    """
    HEADER_STRUCT = "posix_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file)
        header_size = snull(header.size)
        try:
            int(header_size, 8)
        except ValueError:
            return

        file.seek(start_offset)
        end_offset = _get_tar_end_offset(file)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["tar", "xvf", inpath, "--directory", outdir]
