import binascii
import glob
import io
import platform
import shlex
import subprocess
from pathlib import Path

import attrs
import pytest
from lark.lark import Lark
from lark.visitors import Discard, Transformer
from pytest_cov.embed import cleanup_on_sigterm
from unblob_native.sandbox import AccessFS, SandboxError, restrict_access

from unblob.finder import build_hyperscan_database
from unblob.logging import configure_logger
from unblob.models import ProcessResult
from unblob.processing import ExtractionConfig
from unblob.report import ExtractCommandFailedReport


@pytest.fixture(scope="session", autouse=True)
def configure_logging(tmp_path_factory):
    extract_root = tmp_path_factory.mktemp("extract")
    log_path = tmp_path_factory.mktemp("logs") / "unblob.log"
    configure_logger(verbosity_level=3, extract_root=extract_root, log_path=log_path)

    # https://pytest-cov.readthedocs.io/en/latest/subprocess-support.html#if-you-use-multiprocessing-process
    cleanup_on_sigterm()


def gather_integration_tests(test_data_path: Path):
    # Path.glob() trips on some invalid files
    test_input_dirs = [
        Path(p)
        for p in glob.iglob(  # noqa: PTH207
            f"{test_data_path}/**/__input__", recursive=True
        )
    ]
    test_case_dirs = [p.parent for p in test_input_dirs]
    test_output_dirs = [p / "__output__" for p in test_case_dirs]
    test_ids = [
        f"{str(p.relative_to(test_data_path)).replace('/', '.')}"
        for p in test_case_dirs
    ]

    for input_dir, output_dir, test_id in zip(
        test_input_dirs, test_output_dirs, test_ids
    ):
        assert list(input_dir.iterdir()) != [], (
            f"Integration test input dir should contain at least 1 file: {input_dir}"
        )

        yield pytest.param(input_dir, output_dir, id=test_id)


@pytest.fixture
def extraction_config(tmp_path: Path):
    config = ExtractionConfig(
        extract_root=tmp_path,
        randomness_depth=0,
        keep_extracted_chunks=True,
    )

    # Warmup lru_cache before ``process_file`` forks, so child
    # processes can reuse the prebuilt databases without overhead
    build_hyperscan_database(config.handlers)

    return config


def check_output_is_the_same(reference_dir: Path, extract_dir: Path):
    __tracebackhide__ = True

    diff_command = [
        "diff",
        "--recursive",
        "--unified",
        # fix for potential symlinks
        "--no-dereference",
        # Non-unicode files would produce garbage output
        # showing file names which are different should be helpful
        "--brief",
        "--exclude",
        ".gitkeep",
        # Special files in test samples follows a strict naming convention
        # so that we can have them without triggering errors on diff.
        # Example diff with special files: https://www.mail-archive.com/bug-diffutils@gnu.org/msg00863.html
        "--exclude",
        "*.socket",
        "--exclude",
        "*.symlink",
        "--exclude",
        "*.fifo",
        str(reference_dir),
        str(extract_dir),
    ]

    try:
        subprocess.run(diff_command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        runnable_diff_command = shlex.join(diff_command)
        pytest.fail(f"\nDiff command: {runnable_diff_command}\n{exc.stdout}\n")


def check_result(reports: ProcessResult):
    __tracebackhide__ = True
    # filter out error reports about truncated integration test files
    errors = [
        error
        for error in reports.errors
        if not (
            isinstance(error, ExtractCommandFailedReport)
            and error.stderr == b"\nERRORS:\nUnexpected end of archive\n\n"
        )
    ]
    assert errors == [], "Unexpected error reports"


def unhex(hexdump: str) -> bytes:
    """Unparses hexdump back to binary representation.

    In addition to basic parsing the following extra features are supported:

    * line comments starting with ``#``
    * squeezing (repetition of previous line) indicated via ``*`` (see: man 1 hexdump)

    Relative position of data is kept in the result object. This means
    that the offset indicator at the beginning of each line is
    significant, each line will be stored at the position indicated
    relative to the start position.

    The printable ASCII column is discarded during parsing.

    NOTE: all lines MUST contain exactly 16 bytes, except the last line, which can have less.
    """
    parsed = _hexdump_parser.parse(hexdump)
    return _HexDumpToBin().transform(parsed)


BYTES_PER_LINE = 16


_hexdump_parser = Lark(
    """
    %import common.NEWLINE
    %import common.HEXDIGIT

    start:   line (_NEWLINE line)* _NEWLINE?
    line:    address [_SEPARATOR hex _SEPARATOR "|"? ascii "|"?]  -> canonical
             | SQUEEZE                                            -> squeezed
    address: HEXDIGIT+                                            -> join
    hex:     HEXDIGIT+ (_SPACE* HEXDIGIT)+                        -> join
    ascii:   CHAR+                                                -> join
    CHAR:    /./
    SQUEEZE: "*"

    _SEPARATOR: ": " | "  "
    _SPACE:     " "
    _NEWLINE:   NEWLINE
"""
)


@attrs.define
class _HexdumpLine:
    offset: int
    data: bytes

    @classmethod
    def from_bytes(cls, offset, data):
        offset = int.from_bytes(binascii.unhexlify(offset), byteorder="big")
        data = binascii.unhexlify(data) if data else b""
        return cls(offset, data)

    def __len__(self):
        return len(self.data)


class _HexDumpToBin(Transformer):
    def __init__(self):
        super().__init__(visit_tokens=False)
        self._last_line = None
        self._squeezing = False

    def join(self, s):
        return "".join(s.strip() for s in s)

    def canonical(self, s):
        line = _HexdumpLine.from_bytes(s[0], s[1])
        if self._squeezing:
            self._squeezing = False
            line = self._squeeze_in_data(line)
        self._last_line = line
        return self._last_line

    def _squeeze_in_data(self, line: _HexdumpLine) -> _HexdumpLine:
        if not self._last_line:
            raise ValueError("Squeezed line cannot be the first line in a hexdump")

        assert len(self._last_line) % BYTES_PER_LINE == 0

        delta = line.offset - (self._last_line.offset + len(self._last_line))
        count = delta // BYTES_PER_LINE

        return _HexdumpLine(
            self._last_line.offset + len(self._last_line),
            self._last_line.data[-BYTES_PER_LINE:] * count + line.data,
        )

    def squeezed(self, _s):
        self._squeezing = True
        return Discard

    def start(self, s):
        rv = io.BytesIO()
        for line in s:
            rv.write(line.data)

        return rv.getvalue()


def is_sandbox_available():
    is_sandbox_available = True

    try:
        restrict_access(AccessFS.read_write("/"))
    except SandboxError:
        is_sandbox_available = False

    if platform.architecture == "x86_64" and platform.system == "linux":
        assert is_sandbox_available, "Sandboxing should work at least on Linux-x86_64"

    return is_sandbox_available
