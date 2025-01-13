import io
from pathlib import Path
from typing import Optional

import attrs
from pyperscan import Flag, Pattern, Scan, StreamDatabase
from structlog import get_logger

from unblob.file_utils import File, iterate_file, stream_scan
from unblob.models import (
    Endian,
    Extractor,
    Handler,
    HexString,
    StructParser,
    ValidChunk,
)

logger = get_logger()

FOOTER_LEN = 74
SECRET = "QNAPNASVERSION"  # noqa: S105

C_DEFINITIONS = """
    typedef struct qnap_header {
        char    magic[6];
        uint32  encrypted_len;
        char    device_id[16];
        char    file_version[16];
        char    firmware_date[16];
        char    revision[16];
    } qnap_header_t;
"""
FOOTER_PATTERN = [
    HexString("69 63 70 6e 61 73"),  # encrypted gzip stream start bytes
]


@attrs.define
class QTSSearchContext:
    start_offset: int
    file: File
    end_offset: int


def is_valid_header(header) -> bool:
    try:
        header.device_id.decode("utf-8")
        header.file_version.decode("utf-8")
        header.firmware_date.decode("utf-8")
        header.revision.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _hyperscan_match(
    context: QTSSearchContext, pattern_id: int, offset: int, end: int
) -> Scan:
    del pattern_id, end  # unused arguments
    if offset < context.start_offset:
        return Scan.Continue
    context.file.seek(offset, io.SEEK_SET)
    struct_parser = StructParser(C_DEFINITIONS)
    header = struct_parser.parse("qnap_header_t", context.file, Endian.LITTLE)
    logger.debug("qnap_header_t", header=header)

    if is_valid_header(header):
        context.end_offset = context.file.tell()
        return Scan.Terminate
    return Scan.Continue


def build_stream_end_scan_db(pattern_list):
    return StreamDatabase(
        *(Pattern(p.as_regex(), Flag.SOM_LEFTMOST, Flag.DOTALL) for p in pattern_list)
    )


hyperscan_stream_end_magic_db = build_stream_end_scan_db(FOOTER_PATTERN)


class QnapExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        outpath = outdir.joinpath(f"{inpath.name}.decrypted")
        with File.from_path(inpath) as file:
            file.seek(-FOOTER_LEN, io.SEEK_END)
            header = self._struct_parser.parse("qnap_header_t", file, Endian.LITTLE)
            eof = file.tell()
            cryptor = Cryptor(SECRET + header.file_version.decode("utf-8")[0])
            with outpath.open("wb") as outfile:
                for chunk in iterate_file(file, 0, header.encrypted_len, 1024):
                    outfile.write(cryptor.decrypt_chunk(chunk))
                for chunk in iterate_file(
                    file,
                    header.encrypted_len,
                    eof - FOOTER_LEN - header.encrypted_len,
                    1024,
                ):
                    outfile.write(chunk)


class QnapHandler(Handler):
    NAME = "qnap_nas"

    PATTERNS = [
        HexString("F5 7B 47 03"),
    ]
    EXTRACTOR = QnapExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        context = QTSSearchContext(start_offset=start_offset, file=file, end_offset=-1)

        try:
            scanner = hyperscan_stream_end_magic_db.build(context, _hyperscan_match)  # type: ignore
            stream_scan(scanner, file)
        except Exception as e:
            logger.debug(
                "Error scanning for QNAP patterns",
                error=e,
            )
        if context.end_offset > 0:
            return ValidChunk(start_offset=start_offset, end_offset=context.end_offset)
        return None


# https://gist.github.com/ulidtko/966277a465f1856109b2d2674dcee741#file-qnap-qts-fw-cryptor-py-L114
class Cryptor:
    def __init__(self, secret):
        self.secret = list(bytes(secret, "ascii"))
        self.n = len(secret) // 2
        if self.n % 2 == 0:
            self.secret.append(0)
        self.precompute_k()
        self.acc = 0
        self.y = 0
        self.z = 0

    def scan(self, f, xs, s0):
        s = s0
        for x in xs:
            w, s = f(s, x)
            yield w

    def promote(self, char):
        return char if char < 0x80 else char - 0x101

    def precompute_k(self):
        self.k = {acc: self.table_for_acc(acc) for acc in range(256)}

    def table_for_acc(self, a):
        ks = [
            0xFFFFFFFF
            & (
                (self.promote(self.secret[2 * i] ^ a) << 8)
                + (self.secret[2 * i + 1] ^ a)
            )
            for i in range(self.n)
        ]

        def kstep(st, q):
            x = st ^ q
            y = self.lcg(x)
            z = 0xFFFF & (0x15A * x)
            return (z, y), y

        return list(self.scan(kstep, ks, 0))

    def lcg(self, x):
        return 0xFFFF & (0x4E35 * x + 1)

    def kdf(self):
        """self.secret -> 8bit hash (+ state effects)."""
        tt = self.k[self.acc]
        res = 0
        for i in range(self.n):
            yy = self.y
            self.y, t2 = tt[i]
            self.z = 0xFFFF & (self.y + yy + 0x4E35 * (self.z + i))
            res = res ^ t2 ^ self.z
        hi, lo = res >> 8, res & 0xFF
        return hi ^ lo

    def decrypt_byte(self, v):
        k = self.kdf()
        r = 0xFF & (v ^ k)
        self.acc = self.acc ^ r
        return r

    def decrypt_chunk(self, chunk):
        return bytes(map(self.decrypt_byte, chunk))
