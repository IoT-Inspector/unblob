import multiprocessing
import shutil
from collections.abc import Iterable, Sequence
from operator import attrgetter
from pathlib import Path
from typing import Optional, Union

import attrs
import magic
import plotext as plt
from structlog import get_logger
from unblob_native import math_tools as mt

from unblob.handlers import BUILTIN_DIR_HANDLERS, BUILTIN_HANDLERS, Handlers

from .extractor import carve_unknown_chunk, carve_valid_chunk, fix_extracted_directory
from .file_utils import InvalidInputFormat, iterate_file
from .finder import search_chunks
from .iter_utils import pairwise
from .logging import noformat
from .models import (
    Chunk,
    DirectoryHandler,
    DirectoryHandlers,
    ExtractError,
    File,
    MultiFile,
    PaddingChunk,
    ProcessResult,
    Task,
    TaskResult,
    UnknownChunk,
    ValidChunk,
)
from .pool import make_pool
from .report import (
    CalculateMultiFileExceptionReport,
    CarveDirectoryReport,
    FileMagicReport,
    HashReport,
    MultiFileCollisionReport,
    OutputDirectoryExistsReport,
    RandomnessMeasurements,
    RandomnessReport,
    Report,
    StatReport,
    UnknownError,
)
from .ui import NullProgressReporter, ProgressReporter

logger = get_logger()

DEFAULT_DEPTH = 10
DEFAULT_PROCESS_NUM = multiprocessing.cpu_count()
DEFAULT_SKIP_MAGIC = (
    "BFLT",
    "Composite Document File V2 Document",
    "Erlang BEAM file",
    "GIF",
    "GNU message catalog",
    "HP Printer Job Language",
    "Intel serial flash for PCH ROM",
    "JPEG",
    "Java module image",
    "MPEG",
    "MS Windows icon resource",
    "Macromedia Flash data",
    "Microsoft Excel",
    "Microsoft PowerPoint",
    "Microsoft Word",
    "OpenDocument",
    "PDF document",
    "PNG",
    "SQLite",
    "TrueType Font data",
    "Web Open Font Format",
    "Windows Embedded CE binary image",
    "Xilinx BIT data",
    "compiled Java class",
    "magic binary file",
    "python",  #   # (e.g. python 2.7 byte-compiled)
)
DEFAULT_SKIP_EXTENSION = (".rlib",)


@attrs.define(kw_only=True)
class ExtractionConfig:
    extract_root: Path = attrs.field(converter=lambda value: value.resolve())
    force_extract: bool = False
    randomness_depth: int
    randomness_plot: bool = False
    max_depth: int = DEFAULT_DEPTH
    skip_magic: Iterable[str] = DEFAULT_SKIP_MAGIC
    skip_extension: Iterable[str] = DEFAULT_SKIP_EXTENSION
    skip_extraction: bool = False
    process_num: int = DEFAULT_PROCESS_NUM
    keep_extracted_chunks: bool = False
    extract_suffix: str = "_extract"
    carve_suffix: str = "_extract"
    handlers: Handlers = BUILTIN_HANDLERS
    dir_handlers: DirectoryHandlers = BUILTIN_DIR_HANDLERS
    verbose: int = 1
    progress_reporter: type[ProgressReporter] = NullProgressReporter

    def _get_output_path(self, path: Path) -> Path:
        """Return path under extract root."""
        try:
            relative_path = path.relative_to(self.extract_root)
        except ValueError:
            # path is not inside root, i.e. it is an input file
            relative_path = Path(path.name)
        return (self.extract_root / relative_path).expanduser().resolve()

    def get_extract_dir_for(self, path: Path) -> Path:
        return self._get_output_path(path.with_name(path.name + self.extract_suffix))

    def get_carve_dir_for(self, path: Path) -> Path:
        return self._get_output_path(path.with_name(path.name + self.carve_suffix))


def process_file(
    config: ExtractionConfig, input_path: Path, report_file: Optional[Path] = None
) -> ProcessResult:
    task = Task(
        blob_id="",
        path=input_path,
        depth=0,
    )

    if not input_path.is_file():
        raise ValueError("input_path is not a file", input_path)

    extract_dir = config.get_extract_dir_for(input_path)
    if config.force_extract and extract_dir.exists():
        logger.info("Removing extract dir", path=extract_dir)
        shutil.rmtree(extract_dir)

    carve_dir = config.get_carve_dir_for(input_path)
    if config.force_extract and carve_dir.exists():
        logger.info("Removing carve dir", path=carve_dir)
        shutil.rmtree(carve_dir)

    if not prepare_report_file(config, report_file):
        logger.error(
            "File not processed, as report could not be written", file=input_path
        )
        return ProcessResult()

    process_result = _process_task(config, task)

    if report_file:
        write_json_report(report_file, process_result)

    return process_result


def _process_task(config: ExtractionConfig, task: Task) -> ProcessResult:
    processor = Processor(config)
    aggregated_result = ProcessResult()

    progress_reporter = config.progress_reporter()

    def process_result(pool, result):
        progress_reporter.update(result)

        for new_task in result.subtasks:
            pool.submit(new_task)
        aggregated_result.register(result)

    pool = make_pool(
        process_num=config.process_num,
        handler=processor.process_task,
        result_callback=process_result,
    )

    with pool, progress_reporter:
        pool.submit(task)
        pool.process_until_done()

    return aggregated_result


def prepare_report_file(config: ExtractionConfig, report_file: Optional[Path]) -> bool:
    """Prevent report writing failing after an expensive extraction.

    Should be called before processing tasks.

    Returns True if there is no foreseen problem,
            False if report writing is known in advance to fail.
    """
    if not report_file:
        # we will not write report at all
        return True

    if report_file.exists():
        if config.force_extract:
            logger.warning("Overwriting existing report file", path=report_file)
            try:
                report_file.write_text("")
            except OSError as e:
                logger.error(
                    "Can not overwrite existing report file",
                    path=report_file,
                    msg=str(e),
                )
                return False
        else:
            logger.error(
                "Report file exists and --force not specified", path=report_file
            )
            return False
    return True


def write_json_report(report_file: Path, process_result: ProcessResult):
    try:
        report_file.write_text(process_result.to_json())
    except OSError as e:
        logger.error("Can not write JSON report", path=report_file, msg=str(e))
    except Exception:
        logger.exception("Can not write JSON report", path=report_file)
    else:
        logger.info("JSON report written", path=report_file)


class Processor:
    def __init__(self, config: ExtractionConfig):
        self._config = config
        # libmagic helpers
        # file magic uses a rule-set to guess the file type, however as rules are added they could
        # shadow each other. File magic uses rule priorities to determine which is the best matching
        # rule, however this could shadow other valid matches as well, which could eventually break
        # any further processing that depends on magic.
        # By enabling keep_going (which eventually enables MAGIC_CONTINUE) all matching patterns
        # will be included in the magic string at the cost of being a bit slower, but increasing
        # accuracy by no shadowing rules.
        self._get_magic = magic.Magic(keep_going=True).from_file
        self._get_mime_type = magic.Magic(mime=True).from_file

    def process_task(self, task: Task) -> TaskResult:
        result = TaskResult(task)
        try:
            self._process_task(result, task)
        except Exception as exc:
            self._process_error(result, exc)
        return result

    def _process_error(self, result: TaskResult, exc: Exception):
        error_report = UnknownError(exception=exc)
        result.add_report(error_report)
        logger.exception("Unknown error happened", exc_info=exc)

    def _process_task(self, result: TaskResult, task: Task):
        stat_report = StatReport.from_path(task.path)
        result.add_report(stat_report)
        log = logger.bind(path=task.path)

        if task.depth >= self._config.max_depth:
            # TODO: Use the reporting feature to warn the user (ONLY ONCE) at the end of execution, that this limit was reached.
            log.debug(
                "Reached maximum depth, stop further processing", depth=task.depth
            )
            return

        if stat_report.is_dir:
            if not task.is_multi_file:
                _DirectoryTask(self._config, task, result).process()
            return

        if not stat_report.is_file:
            log.debug(
                "Ignoring special file (link, chrdev, blkdev, fifo, socket, door)."
            )
            return

        magic = self._get_magic(task.path)
        mime_type = self._get_mime_type(task.path)
        logger.debug("Detected file-magic", magic=magic, path=task.path, _verbosity=2)

        magic_report = FileMagicReport(magic=magic, mime_type=mime_type)
        result.add_report(magic_report)

        hash_report = HashReport.from_path(task.path)
        result.add_report(hash_report)

        if task.is_multi_file:
            # The file has been processed as part of a MultiFile, we just run the task to gather reports
            return

        if stat_report.size == 0:
            log.debug("Ignoring empty file")
            return

        should_skip_file = any(
            magic.startswith(pattern) for pattern in self._config.skip_magic
        )
        should_skip_file |= task.path.suffix in self._config.skip_extension

        if should_skip_file:
            log.debug(
                "Ignoring file based on magic or extension.",
                magic=magic,
                extension=task.path.suffix,
            )
            return

        _FileTask(self._config, task, stat_report.size, result).process()


class DirectoryProcessingError(Exception):
    def __init__(self, message: str, report: Report):
        super().__init__()
        self.message = message
        self.report: Report = report


class _DirectoryTask:
    def __init__(self, config: ExtractionConfig, dir_task: Task, result: TaskResult):
        self.config = config
        self.dir_task = dir_task
        self.result = result

    def process(self):
        logger.debug("Processing directory", path=self.dir_task.path)

        try:
            processed_paths, extract_dirs = self._process_directory()
        except DirectoryProcessingError as e:
            logger.error(e.message, report=e.report)
            self.result.add_report(e.report)
            return

        self._iterate_directory(extract_dirs, processed_paths)

        self._iterate_processed_files(processed_paths)

    def _process_directory(self) -> tuple[set[Path], set[Path]]:
        processed_paths: set[Path] = set()
        extract_dirs: set[Path] = set()
        for dir_handler_class in self.config.dir_handlers:
            dir_handler = dir_handler_class()

            for path in dir_handler.PATTERN.get_files(self.dir_task.path):
                multi_file = self._calculate_multifile(dir_handler, path, self.result)

                if multi_file is None:
                    continue

                multi_file.handler = dir_handler

                self._check_conflicting_files(multi_file, processed_paths)

                extract_dir = self._extract_multi_file(multi_file)

                # Process files in extracted directory
                if extract_dir.exists():
                    self.result.add_subtask(
                        Task(
                            blob_id=multi_file.id,
                            path=extract_dir,
                            depth=self.dir_task.depth + 1,
                        )
                    )
                    extract_dirs.add(extract_dir)

                processed_paths.update(multi_file.paths)
        return processed_paths, extract_dirs

    @staticmethod
    def _calculate_multifile(
        dir_handler: DirectoryHandler, path: Path, task_result: TaskResult
    ) -> Optional[MultiFile]:
        try:
            return dir_handler.calculate_multifile(path)
        except InvalidInputFormat as exc:
            logger.debug(
                "Invalid MultiFile format",
                exc_info=exc,
                handler=dir_handler.NAME,
                path=path,
                _verbosity=2,
            )
        except Exception as exc:
            error_report = CalculateMultiFileExceptionReport(
                handler=dir_handler.NAME,
                exception=exc,
                path=path,
            )
            task_result.add_report(error_report)
            logger.warning(
                "Unhandled Exception during multi file calculation",
                **error_report.asdict(),
            )

    def _check_conflicting_files(
        self, multi_file: MultiFile, processed_paths: set[Path]
    ):
        conflicting_paths = processed_paths.intersection(set(multi_file.paths))
        if conflicting_paths:
            raise DirectoryProcessingError(
                "Conflicting match on files",
                report=MultiFileCollisionReport(
                    paths=conflicting_paths, handler=multi_file.handler.NAME
                ),
            )

    def _extract_multi_file(self, multi_file: MultiFile) -> Path:
        extract_dir = self.config.get_extract_dir_for(
            self.dir_task.path / multi_file.name
        )
        if extract_dir.exists():
            raise DirectoryProcessingError(
                "Skipped: extraction directory exists",
                report=multi_file.as_report(
                    [OutputDirectoryExistsReport(path=extract_dir)]
                ),
            )

        extraction_reports = []
        try:
            if result := multi_file.extract(extract_dir):
                extraction_reports.extend(result.reports)
        except ExtractError as e:
            extraction_reports.extend(e.reports)
        except Exception as exc:
            logger.exception("Unknown error happened while extracting MultiFile")
            extraction_reports.append(UnknownError(exception=exc))

        self.result.add_report(multi_file.as_report(extraction_reports))

        fix_extracted_directory(extract_dir, self.result)

        return extract_dir

    def _iterate_processed_files(self, processed_paths):
        for path in processed_paths:
            self.result.add_subtask(
                Task(
                    blob_id=self.dir_task.blob_id,
                    path=path,
                    depth=self.dir_task.depth,
                    is_multi_file=True,
                )
            )

    def _iterate_directory(self, extract_dirs, processed_paths):
        for path in self.dir_task.path.iterdir():
            if path in extract_dirs or path in processed_paths:
                continue

            self.result.add_subtask(
                Task(
                    blob_id=self.dir_task.blob_id,
                    path=path,
                    depth=self.dir_task.depth,
                )
            )


def is_padding(file: File, chunk: UnknownChunk):
    return len(set(file[chunk.start_offset : chunk.end_offset])) == 1


def process_patterns(
    unknown_chunks: list[UnknownChunk], file: File
) -> list[Union[UnknownChunk, PaddingChunk]]:
    processed_chunks = []
    for unknown_chunk in unknown_chunks:
        if is_padding(file, unknown_chunk):
            processed_chunks.append(
                PaddingChunk(
                    start_offset=unknown_chunk.start_offset,
                    end_offset=unknown_chunk.end_offset,
                    id=unknown_chunk.id,
                    file=unknown_chunk.file,
                )
            )
        else:
            processed_chunks.append(unknown_chunk)
    return processed_chunks


class _FileTask:
    def __init__(
        self,
        config: ExtractionConfig,
        task: Task,
        size: int,
        result: TaskResult,
    ):
        self.config = config
        self.task = task
        self.size = size
        self.result = result

    def process(self):
        logger.debug("Processing file", path=self.task.path, size=self.size)

        with File.from_path(self.task.path) as file:
            all_chunks = search_chunks(
                file, self.size, self.config.handlers, self.result
            )
            outer_chunks = remove_inner_chunks(all_chunks)
            unknown_chunks = calculate_unknown_chunks(outer_chunks, self.size)
            unknown_chunks = process_patterns(unknown_chunks, file)
            assign_file_to_chunks(outer_chunks, file=file)
            assign_file_to_chunks(unknown_chunks, file=file)

            if outer_chunks or unknown_chunks:
                self._process_chunks(file, outer_chunks, unknown_chunks)
            else:
                # we don't consider whole files as unknown chunks, but we still want to
                # calculate randomness for whole files which produced no valid chunks
                randomness = self._calculate_randomness(self.task.path)
                if randomness:
                    self.result.add_report(randomness)

    def _process_chunks(
        self,
        file: File,
        outer_chunks: list[ValidChunk],
        unknown_chunks: list[Union[UnknownChunk, PaddingChunk]],
    ):
        if unknown_chunks:
            logger.warning("Found unknown Chunks", chunks=unknown_chunks)

        if self.config.skip_extraction:
            for chunk in unknown_chunks:
                self.result.add_report(chunk.as_report(randomness=None))
            for chunk in outer_chunks:
                self.result.add_report(chunk.as_report(extraction_reports=[]))
            return

        is_whole_file_chunk = len(outer_chunks) + len(unknown_chunks) == 1
        if is_whole_file_chunk:
            # skip carving, extract directly the whole file (chunk)
            carved_path = self.task.path
            for chunk in outer_chunks:
                self._extract_chunk(
                    carved_path,
                    chunk,
                    self.config.get_extract_dir_for(carved_path),
                    # since we do not carve, we want to keep the input around
                    remove_extracted_input=False,
                )
        else:
            self._carve_then_extract_chunks(file, outer_chunks, unknown_chunks)

    def _carve_then_extract_chunks(self, file, outer_chunks, unknown_chunks):
        assert not self.config.skip_extraction

        carve_dir = self.config.get_carve_dir_for(self.task.path)

        # report the technical carve directory explicitly
        self.result.add_report(CarveDirectoryReport(carve_dir=carve_dir))

        if carve_dir.exists():
            # Carve directory is not supposed to exist, it is usually a simple mistake of running
            # unblob again without cleaning up or using --force.
            # It would cause problems continuing, as it would mix up original and extracted files,
            # and it would just introduce weird, non-deterministic problems due to interference on paths
            # by multiple workers (parallel processing, modifying content (fix_symlink),
            # and `mmap` + open for write with O_TRUNC).
            logger.error("Skipped: carve directory exists", carve_dir=carve_dir)
            self.result.add_report(OutputDirectoryExistsReport(path=carve_dir))
            return

        for chunk in unknown_chunks:
            carved_unknown_path = carve_unknown_chunk(carve_dir, file, chunk)
            randomness = self._calculate_randomness(carved_unknown_path)
            self.result.add_report(chunk.as_report(randomness=randomness))

        for chunk in outer_chunks:
            carved_path = carve_valid_chunk(carve_dir, file, chunk)

            self._extract_chunk(
                carved_path,
                chunk,
                self.config.get_extract_dir_for(carved_path),
                # when a carved chunk is successfully extracted, usually
                # we want to get rid of it, as its data is available in
                # extracted format, and the raw data is still part of
                # the file the chunk belongs to
                remove_extracted_input=not self.config.keep_extracted_chunks,
            )

    def _calculate_randomness(self, path: Path) -> Optional[RandomnessReport]:
        if self.task.depth < self.config.randomness_depth:
            report = calculate_randomness(path)
            if self.config.randomness_plot:
                logger.debug(
                    "Randomness chart",
                    # New line so that chart title will be aligned correctly in the next line
                    chart="\n" + format_randomness_plot(report),
                    path=path,
                    _verbosity=3,
                )
            return report
        return None

    def _extract_chunk(
        self,
        carved_path: Path,
        chunk: ValidChunk,
        extract_dir: Path,
        *,
        remove_extracted_input: bool,
    ):
        if extract_dir.exists():
            # Extraction directory is not supposed to exist, it mixes up original and extracted files,
            # and it would just introduce weird, non-deterministic problems due to interference on paths
            # by multiple workers (parallel processing, modifying content (fix_symlink),
            # and `mmap` + open for write with O_TRUNC).
            logger.error(
                "Skipped: extraction directory exists",
                extract_dir=extract_dir,
                chunk=chunk,
            )
            self.result.add_report(
                chunk.as_report([OutputDirectoryExistsReport(path=extract_dir)])
            )
            return

        if self.config.skip_extraction:
            fix_extracted_directory(extract_dir, self.result)
            return

        extraction_reports = []
        try:
            if result := chunk.extract(carved_path, extract_dir):
                extraction_reports.extend(result.reports)

            if remove_extracted_input:
                logger.debug("Removing extracted chunk", path=carved_path)
                carved_path.unlink()

        except ExtractError as e:
            extraction_reports.extend(e.reports)
        except Exception as exc:
            logger.exception("Unknown error happened while extracting chunk")
            extraction_reports.append(UnknownError(exception=exc))

        self.result.add_report(chunk.as_report(extraction_reports))

        # we want to get consistent partial output even in case of unforeseen problems
        fix_extracted_directory(extract_dir, self.result)
        delete_empty_extract_dir(extract_dir)

        if extract_dir.exists():
            self.result.add_subtask(
                Task(
                    blob_id=chunk.id,
                    path=extract_dir,
                    depth=self.task.depth + 1,
                )
            )


def assign_file_to_chunks(chunks: Sequence[Chunk], file: File):
    for chunk in chunks:
        assert chunk.file is None
        chunk.file = file


def delete_empty_extract_dir(extract_dir: Path):
    if extract_dir.exists() and not any(extract_dir.iterdir()):
        extract_dir.rmdir()


def remove_inner_chunks(chunks: list[ValidChunk]) -> list[ValidChunk]:
    """Remove all chunks from the list which are within another bigger chunks."""
    if not chunks:
        return []

    chunks_by_size = sorted(chunks, key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks_by_size[0]]
    for chunk in chunks_by_size[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)

    outer_count = len(outer_chunks)
    removed_count = len(chunks) - outer_count
    logger.debug(
        "Removed inner chunks",
        outer_chunk_count=noformat(outer_count),
        removed_inner_chunk_count=noformat(removed_count),
        _verbosity=2,
    )
    return outer_chunks


def calculate_unknown_chunks(
    chunks: list[ValidChunk], file_size: int
) -> list[UnknownChunk]:
    """Calculate the empty gaps between chunks."""
    if not chunks or file_size == 0:
        return []

    sorted_by_offset = sorted(chunks, key=attrgetter("start_offset"))

    unknown_chunks = []

    first = sorted_by_offset[0]
    if first.start_offset != 0:
        unknown_chunk = UnknownChunk(start_offset=0, end_offset=first.start_offset)
        unknown_chunks.append(unknown_chunk)

    for chunk, next_chunk in pairwise(sorted_by_offset):
        diff = next_chunk.start_offset - chunk.end_offset
        if diff != 0:
            unknown_chunk = UnknownChunk(
                start_offset=chunk.end_offset,
                end_offset=next_chunk.start_offset,
            )
            unknown_chunks.append(unknown_chunk)

    last = sorted_by_offset[-1]
    if last.end_offset < file_size:
        unknown_chunk = UnknownChunk(
            start_offset=last.end_offset,
            end_offset=file_size,
        )
        unknown_chunks.append(unknown_chunk)

    return unknown_chunks


def calculate_randomness(path: Path) -> RandomnessReport:
    """Calculate and log shannon entropy divided by 8 for the file in chunks.

    Shannon entropy returns the amount of information (in bits) of some numeric
    sequence. We calculate the average entropy of byte chunks, which in theory
    can contain 0-8 bits of entropy. We normalize it for visualization to a
    0-100% scale, to make it easier to interpret the graph.

    The chi square distribution is calculated for the stream of bytes in the
    chunk and expressed as an absolute number and a percentage which indicates
    how frequently a truly random sequence would exceed the value calculated.
    """
    shannon_percentages = []
    chi_square_percentages = []

    # We could use the chunk size instead of another syscall,
    # but we rely on the actual file size written to the disk
    file_size = path.stat().st_size
    logger.debug("Calculating entropy for file", path=path, size=file_size)

    # Smaller chunk size would be very slow to calculate.
    # 1Mb chunk size takes ~ 3sec for a 4,5 GB file.
    block_size = calculate_block_size(
        file_size,
        chunk_count=80,
        min_limit=1024,
        max_limit=1024 * 1024,
    )

    shannon_entropy_sum = 0.0
    chisquare_probability_sum = 0.0
    with File.from_path(path) as file:
        for chunk in iterate_file(file, 0, file_size, buffer_size=block_size):
            shannon_entropy = mt.shannon_entropy(chunk)
            shannon_entropy_percentage = round(shannon_entropy / 8 * 100, 2)
            shannon_percentages.append(shannon_entropy_percentage)
            shannon_entropy_sum += shannon_entropy * len(chunk)

            chi_square_probability = mt.chi_square_probability(chunk)
            chisquare_probability_percentage = round(chi_square_probability * 100, 2)
            chi_square_percentages.append(chisquare_probability_percentage)
            chisquare_probability_sum += chi_square_probability * len(chunk)

    report = RandomnessReport(
        shannon=RandomnessMeasurements(
            percentages=shannon_percentages,
            block_size=block_size,
            mean=shannon_entropy_sum / file_size / 8 * 100,
        ),
        chi_square=RandomnessMeasurements(
            percentages=chi_square_percentages,
            block_size=block_size,
            mean=chisquare_probability_sum / file_size * 100,
        ),
    )

    logger.debug(
        "Shannon entropy calculated",
        path=path,
        size=file_size,
        block_size=report.shannon.block_size,
        mean=round(report.shannon.mean, 2),
        highest=round(report.shannon.highest, 2),
        lowest=round(report.shannon.lowest, 2),
    )
    logger.debug(
        "Chi square probability calculated",
        path=path,
        size=file_size,
        block_size=report.chi_square.block_size,
        mean=round(report.chi_square.mean, 2),
        highest=round(report.chi_square.highest, 2),
        lowest=round(report.chi_square.lowest, 2),
    )

    return report


def calculate_block_size(
    file_size, *, chunk_count: int, min_limit: int, max_limit: int
) -> int:
    """Split the file into even sized chunks, limited by lower and upper values."""
    # We don't care about floating point precision here
    block_size = file_size // chunk_count
    block_size = max(min_limit, block_size)
    block_size = min(block_size, max_limit)
    return block_size  # noqa: RET504


def format_randomness_plot(report: RandomnessReport):
    # start from scratch
    plt.clear_figure()
    # go colorless
    plt.clear_color()
    plt.title("Entropy distribution")
    plt.xlabel(f"{report.shannon.block_size} bytes")

    plt.plot(report.shannon.percentages, label="Shannon entropy (%)", marker="dot")
    plt.plot(
        report.chi_square.percentages,
        label="Chi square probability (%)",
        marker="cross",
    )
    # 16 height leaves no gaps between the lines
    plt.plot_size(100, 16)
    plt.ylim(0, 100)
    # Draw ticks every 1Mb on the x axis.
    plt.xticks(range(len(report.shannon.percentages) + 1))
    # Always show 0% and 100%
    plt.yticks(range(0, 101, 10))

    return plt.build()
