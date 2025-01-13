import hashlib
import stat
import traceback
from enum import Enum
from pathlib import Path
from typing import Optional, Union, final

import attrs


@attrs.define(kw_only=True, frozen=True)
class Report:
    """A common base class for different reports."""

    def __attrs_post_init__(self):
        for field in attrs.fields(type(self)):
            value = getattr(self, field.name)
            if isinstance(value, int):
                object.__setattr__(self, field.name, int(value))

    def asdict(self) -> dict:
        return attrs.asdict(self)


class Severity(Enum):
    """Represents possible problems encountered during execution."""

    ERROR = "ERROR"
    WARNING = "WARNING"


@attrs.define(kw_only=True, frozen=True)
class ErrorReport(Report):
    severity: Severity


def _convert_exception_to_str(obj: Union[str, Exception]) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Exception):
        e: Exception = obj
        return "".join(traceback.format_exception(type(e), e, e.__traceback__))
    raise ValueError("Invalid exception object", obj)


@attrs.define(kw_only=True, frozen=True)
class UnknownError(ErrorReport):
    """Describes an exception raised during file processing."""

    severity: Severity = attrs.field(default=Severity.ERROR)
    exception: Union[str, Exception] = attrs.field(  # pyright: ignore[reportGeneralTypeIssues]
        converter=_convert_exception_to_str
    )
    """Exceptions are also formatted at construct time.

    `attrs` is not integrated enough with type checker/LSP provider `pyright` to include converters.

    See: https://www.attrs.org/en/stable/types.html#pyright
    """


@attrs.define(kw_only=True, frozen=True)
class CalculateChunkExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution."""

    start_offset: int
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str


@attrs.define(kw_only=True, frozen=True)
class CalculateMultiFileExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution."""

    path: Path
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str


@attrs.define(kw_only=True, frozen=True)
class ExtractCommandFailedReport(ErrorReport):
    """Describes an error when failed to run the extraction command."""

    severity: Severity = Severity.WARNING
    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int


@attrs.define(kw_only=True, frozen=True)
class OutputDirectoryExistsReport(ErrorReport):
    severity: Severity = Severity.ERROR
    path: Path


@attrs.define(kw_only=True, frozen=True)
class ExtractorDependencyNotFoundReport(ErrorReport):
    """Describes an error when the dependency of an extractor doesn't exist."""

    severity: Severity = Severity.ERROR
    dependencies: list[str]


@attrs.define(kw_only=True, frozen=True)
class ExtractorTimedOut(ErrorReport):
    """Describes an error when the extractor execution timed out."""

    severity: Severity = Severity.ERROR
    cmd: str
    timeout: float


@attrs.define(kw_only=True, frozen=True)
class MaliciousSymlinkRemoved(ErrorReport):
    """Describes an error when malicious symlinks have been removed from disk."""

    severity: Severity = Severity.WARNING
    link: str
    target: str


@attrs.define(kw_only=True, frozen=True)
class MultiFileCollisionReport(ErrorReport):
    """Describes an error when MultiFiles collide on the same file."""

    severity: Severity = Severity.ERROR
    paths: set[Path]
    handler: str


@attrs.define(kw_only=True, frozen=True)
class StatReport(Report):
    path: Path
    size: int
    is_dir: bool
    is_file: bool
    is_link: bool
    link_target: Optional[Path]

    @classmethod
    def from_path(cls, path: Path):
        st = path.lstat()
        mode = st.st_mode
        try:
            link_target = Path.readlink(path)
        except OSError:
            link_target = None

        return cls(
            path=path,
            size=st.st_size,
            is_dir=stat.S_ISDIR(mode),
            is_file=stat.S_ISREG(mode),
            is_link=stat.S_ISLNK(mode),
            link_target=link_target,
        )


@attrs.define(kw_only=True, frozen=True)
class HashReport(Report):
    md5: str
    sha1: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path):
        chunk_size = 1024 * 64
        md5 = hashlib.md5()  # noqa: S324
        sha1 = hashlib.sha1()  # noqa: S324
        sha256 = hashlib.sha256()

        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return cls(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
        )


@attrs.define(kw_only=True, frozen=True)
class FileMagicReport(Report):
    magic: str
    mime_type: str


@attrs.define(kw_only=True, frozen=True)
class RandomnessMeasurements:
    percentages: list[float]
    block_size: int
    mean: float

    @property
    def highest(self):
        return max(self.percentages)

    @property
    def lowest(self):
        return min(self.percentages)


@attrs.define(kw_only=True, frozen=True)
class RandomnessReport(Report):
    shannon: RandomnessMeasurements
    chi_square: RandomnessMeasurements


@final
@attrs.define(kw_only=True, frozen=True)
class ChunkReport(Report):
    id: str
    handler_name: str
    start_offset: int
    end_offset: int
    size: int
    is_encrypted: bool
    extraction_reports: list[Report]


@final
@attrs.define(kw_only=True, frozen=True)
class UnknownChunkReport(Report):
    id: str
    start_offset: int
    end_offset: int
    size: int
    randomness: Optional[RandomnessReport]


@attrs.define(kw_only=True, frozen=True)
class CarveDirectoryReport(Report):
    carve_dir: Path


@final
@attrs.define(kw_only=True, frozen=True)
class MultiFileReport(Report):
    id: str
    handler_name: str
    name: str
    paths: list[Path]
    extraction_reports: list[Report]


@attrs.define(kw_only=True, frozen=True)
class ExtractionProblem(Report):
    """A non-fatal problem discovered during extraction.

    A report like this still means, that the extraction was successful,
    but there were problems that got resolved.
    The output is expected to be complete, with the exception of
    the reported path.

    Examples
    --------
    - duplicate entries for certain archive formats (tar, zip)
    - unsafe symlinks pointing outside of extraction directory

    """

    problem: str
    resolution: str
    path: Optional[str] = None

    @property
    def log_msg(self):
        return f"{self.problem} {self.resolution}"

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path)


@attrs.define(kw_only=True, frozen=True)
class PathTraversalProblem(ExtractionProblem):
    extraction_path: str

    def log_with(self, logger):
        logger.warning(
            self.log_msg,
            path=self.path,
            extraction_path=self.extraction_path,
        )


@attrs.define(kw_only=True, frozen=True)
class LinkExtractionProblem(ExtractionProblem):
    link_path: str

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, link_path=self.link_path)


@attrs.define(kw_only=True, frozen=True)
class SpecialFileExtractionProblem(ExtractionProblem):
    mode: int
    device: int

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, mode=self.mode, device=self.device)
