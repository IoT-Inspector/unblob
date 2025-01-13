import platform
import sys
import zipfile
from collections.abc import Collection
from pathlib import Path
from statistics import mean
from typing import Optional, TypeVar

import attrs
import pytest

from unblob import handlers
from unblob.extractors.command import Command
from unblob.file_utils import File
from unblob.models import (
    DirectoryExtractor,
    DirectoryHandler,
    Glob,
    Handler,
    MultiFile,
    Regex,
    ReportType,
    SingleFile,
    UnknownChunk,
    ValidChunk,
)
from unblob.processing import (
    ExtractionConfig,
    calculate_block_size,
    calculate_randomness,
    calculate_unknown_chunks,
    format_randomness_plot,
    process_file,
    remove_inner_chunks,
)
from unblob.report import (
    ChunkReport,
    FileMagicReport,
    HashReport,
    MultiFileCollisionReport,
    MultiFileReport,
    OutputDirectoryExistsReport,
    RandomnessMeasurements,
    RandomnessReport,
    StatReport,
    UnknownChunkReport,
    UnknownError,
)

T = TypeVar("T")


def assert_same_chunks(expected, actual, explanation=None):
    """Assert ignoring the chunk.id-s."""
    assert len(expected) == len(actual), explanation
    for e, a in zip(expected, actual):
        assert attrs.evolve(e, id="") == attrs.evolve(a, id=""), explanation


@pytest.mark.parametrize(
    "chunks, expected, explanation",
    [
        ([], [], "Empty list as chunks (No chunk found)"),
        (
            [
                ValidChunk(start_offset=1, end_offset=2),
            ],
            [ValidChunk(start_offset=1, end_offset=2)],
            "Only one chunk",
        ),
        (
            [
                ValidChunk(start_offset=0, end_offset=5),
                ValidChunk(start_offset=1, end_offset=2),
            ],
            [ValidChunk(start_offset=0, end_offset=5)],
            "One chunk within another",
        ),
        (
            [
                ValidChunk(start_offset=10, end_offset=20),
                ValidChunk(start_offset=11, end_offset=13),
                ValidChunk(start_offset=14, end_offset=19),
            ],
            [ValidChunk(start_offset=10, end_offset=20)],
            "Multiple chunks within 1 outer chunk",
        ),
        (
            [
                ValidChunk(start_offset=11, end_offset=13),
                ValidChunk(start_offset=10, end_offset=20),
                ValidChunk(start_offset=14, end_offset=19),
            ],
            [ValidChunk(start_offset=10, end_offset=20)],
            "Multiple chunks within 1 outer chunk, in different order",
        ),
        (
            [
                ValidChunk(start_offset=1, end_offset=5),
                ValidChunk(start_offset=6, end_offset=10),
            ],
            [
                ValidChunk(start_offset=1, end_offset=5),
                ValidChunk(start_offset=6, end_offset=10),
            ],
            "Multiple outer chunks",
        ),
        (
            [
                ValidChunk(start_offset=1, end_offset=5),
                ValidChunk(start_offset=2, end_offset=3),
                ValidChunk(start_offset=6, end_offset=10),
                ValidChunk(start_offset=7, end_offset=8),
            ],
            [
                ValidChunk(start_offset=1, end_offset=5),
                ValidChunk(start_offset=6, end_offset=10),
            ],
            "Multiple outer chunks, with chunks inside",
        ),
    ],
)
def test_remove_inner_chunks(
    chunks: list[ValidChunk], expected: list[ValidChunk], explanation: str
):
    assert_same_chunks(expected, remove_inner_chunks(chunks), explanation)


@pytest.mark.parametrize(
    "chunks, file_size, expected",
    [
        ([], 0, []),
        ([], 10, []),
        ([ValidChunk(start_offset=0x0, end_offset=0x5)], 5, []),
        (
            [
                ValidChunk(start_offset=0x0, end_offset=0x5),
                ValidChunk(start_offset=0x5, end_offset=0xA),
            ],
            10,
            [],
        ),
        (
            [
                ValidChunk(start_offset=0x0, end_offset=0x5),
                ValidChunk(start_offset=0x5, end_offset=0xA),
            ],
            12,
            [UnknownChunk(start_offset=0xA, end_offset=0xC)],
        ),
        (
            [ValidChunk(start_offset=0x3, end_offset=0x5)],
            5,
            [UnknownChunk(start_offset=0x0, end_offset=0x3)],
        ),
        (
            [
                ValidChunk(start_offset=0x0, end_offset=0x5),
                ValidChunk(start_offset=0x7, end_offset=0xA),
            ],
            10,
            [UnknownChunk(start_offset=0x5, end_offset=0x7)],
        ),
        (
            [
                ValidChunk(start_offset=0x8, end_offset=0xA),
                ValidChunk(start_offset=0x0, end_offset=0x5),
                ValidChunk(start_offset=0xF, end_offset=0x14),
            ],
            20,
            [
                UnknownChunk(start_offset=0x5, end_offset=0x8),
                UnknownChunk(start_offset=0xA, end_offset=0xF),
            ],
        ),
    ],
)
def test_calculate_unknown_chunks(
    chunks: list[ValidChunk], file_size: int, expected: list[UnknownChunk]
):
    assert_same_chunks(expected, calculate_unknown_chunks(chunks, file_size))


@pytest.mark.parametrize(
    "file_size, chunk_count, min_limit, max_limit, expected",
    [
        (1000, 1, 10, 100, 100),
        (1000, 10, 10, 100, 100),
        (1000, 100, 10, 100, 10),
    ],
)
def test_calculate_block_size(
    file_size: int, chunk_count: int, min_limit: int, max_limit: int, expected: int
):
    assert expected == calculate_block_size(
        file_size,
        chunk_count=chunk_count,
        min_limit=min_limit,
        max_limit=max_limit,
    )


def test_format_randomness_plot_error():
    with pytest.raises(TypeError):
        format_randomness_plot(
            RandomnessReport(
                shannon=RandomnessMeasurements(percentages=[], block_size=1024, mean=0),
                chi_square=RandomnessMeasurements(
                    percentages=[], block_size=1024, mean=0
                ),
            )
        )


@pytest.mark.parametrize(
    "percentages, block_size",
    [
        pytest.param([0.0] * 100, 1024, id="zero-array"),
        pytest.param([99.99] * 100, 1024, id="99-array"),
        pytest.param([100.0] * 100, 1024, id="100-array"),
        pytest.param([100.0] * 100, -1, id="block_size-can-be-anything1"),
        pytest.param([100.0] * 100, None, id="block_size-can-be-anything2"),
        pytest.param([100.0] * 100, "None", id="block_size-can-be-anything3"),
    ],
)
def test_format_randomness_plot_no_exception(percentages: list[float], block_size: int):
    assert str(block_size) in format_randomness_plot(
        RandomnessReport(
            shannon=RandomnessMeasurements(
                percentages=percentages, block_size=block_size, mean=mean(percentages)
            ),
            chi_square=RandomnessMeasurements(
                percentages=percentages, block_size=block_size, mean=mean(percentages)
            ),
        )
    )


def test_calculate_randomness_no_exception():
    report = calculate_randomness(Path(sys.executable))
    format_randomness_plot(report)


@pytest.mark.parametrize(
    "extract_root, path, result",
    [
        ("/extract", "firmware", "/extract/firmware_extract"),
        ("/extract", "relative/firmware", "/extract/firmware_extract"),
        ("/extract", "/extract/dir/firmware", "/extract/dir/firmware_extract"),
        (
            "/extract/dir",
            "/extract/dir/firmware",
            "/extract/dir/firmware_extract",
        ),
        ("/extract", "/some/place/else/firmware", "/extract/firmware_extract"),
        (
            "extract",
            "/some/place/else/firmware",
            str(Path(".").resolve() / "extract/firmware_extract"),
        ),
    ],
)
def test_ExtractionConfig_get_extract_dir_for(  # noqa: N802
    extract_root: str, path: str, result: str
):
    cfg = ExtractionConfig(extract_root=Path(extract_root), randomness_depth=0)
    assert cfg.get_extract_dir_for(Path(path)) == Path(result)


def mkzip(dir_: Path, output: Path):
    with zipfile.ZipFile(output, "x") as zf:
        for path in dir_.glob("**/*"):
            zf.write(path, path.relative_to(dir_))


@pytest.fixture
def fw(tmp_path: Path):
    # _fixture_fw
    # ├── fw.zip    <------- output
    # ├── internal
    # │   └── fw
    # │       ├── hello
    # │       └── world
    # └── outer
    #     └── fw
    #         └── internal.zip
    base = tmp_path / "_fixture_fw"

    internal = base / "internal"
    (internal / "fw").mkdir(parents=True)
    (internal / "fw/hello").write_bytes(b"hello")
    (internal / "fw/world").write_bytes(b"world")
    outer = base / "outer"
    (outer / "fw").mkdir(parents=True)
    mkzip(internal, outer / "fw/internal.zip")
    mkzip(outer, base / "fw.zip")

    return base / "fw.zip"


def sort_paths(paths: Collection[Path], base: Path) -> tuple[list[Path], list[Path]]:
    """Sorts paths into two bins, the first one will contain subpaths of base, the second are not.

    The first bin will also be converted to relative paths.
    """
    subpaths = []
    outsiders = []
    for path in sorted(paths):
        try:
            subpaths.append(path.relative_to(base))
        except ValueError:
            outsiders.append(path)
    return subpaths, outsiders


def test_process_file_prevents_double_extracts(tmp_path: Path, fw: Path):
    # fw_extract_root
    # └── fw.zip_extract
    #     └── fw
    #         ├── internal.zip
    #         └── internal.zip_extract
    #             └── fw
    #                 ├── hello
    #                 └── world
    fw_extract_root = tmp_path / "fw_extract_root"
    config = ExtractionConfig(extract_root=fw_extract_root, randomness_depth=0)
    process_result = process_file(config, fw)
    assert process_result.errors == []
    extracted_fw_paths, outsiders = sort_paths(
        [t.task.path for t in process_result.results], base=fw_extract_root
    )
    assert outsiders == [fw]

    extracted_fw_zip = tmp_path / "extracted_fw.zip"
    mkzip(fw_extract_root, extracted_fw_zip)

    # fw_extract_of_extract_root
    # └── extracted_fw.zip_extract
    #     └── fw.zip_extract
    #         └── fw
    #             ├── internal.zip
    #             └── internal.zip_extract
    #                 └── fw
    #                     ├── hello
    #                     └── world
    fw_extract_of_extract_root = tmp_path / "fw_extract_of_extract_root"
    config = ExtractionConfig(
        extract_root=fw_extract_of_extract_root, randomness_depth=0
    )
    process_result = process_file(config, extracted_fw_zip)

    # we expect exactly 1 problem reported, related to the extraction of "internal.zip"
    [report] = process_result.errors
    assert isinstance(report, OutputDirectoryExistsReport)
    assert report.path.name == "internal.zip_extract"

    # the rest should be the same, except that the extraction is shifted with one extra directory
    # please note, that repeated processing is also excluded with the below checks
    # "internal.zip_extract" and thus its content must not be processed twice!
    extracted_extracted_fw_paths, outsiders = sort_paths(
        [t.task.path for t in process_result.results],
        base=fw_extract_of_extract_root / "extracted_fw.zip_extract",
    )
    assert outsiders == [extracted_fw_zip]

    assert extracted_extracted_fw_paths == [Path("."), *extracted_fw_paths]


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="non-POSIX path not supported"
)
def test_processing_with_non_posix_paths(tmp_path: Path):
    non_unicode_file = tmp_path / "file-\udce4\udc94"
    non_unicode_file.write_bytes(b"content")

    directory = tmp_path / "dir-\udce4\udc94"
    directory.mkdir(exist_ok=True)
    file_with_non_unicode_dir = directory / "test.txt"
    file_with_non_unicode_dir.write_bytes(b"content")

    extract_root = tmp_path / "extract_root"
    config = ExtractionConfig(extract_root=extract_root, randomness_depth=0)

    for path in (non_unicode_file, file_with_non_unicode_dir):
        process_result = process_file(config, path)
        assert process_result.errors == []
        assert len(process_result.results) == 1
        assert len(process_result.results[0].reports) == 3

        report = process_result.results[0].reports[0]
        assert isinstance(report, StatReport)
        assert report == StatReport(
            path=path,
            size=7,
            is_dir=False,
            is_file=True,
            is_link=False,
            link_target=None,
        )


def test_randomness_calculation(tmp_path: Path):
    """Process a file with unknown chunk and a zip file with randomness calculation enabled.

    The input file structure is
    - zip-chunk
        - empty.txt
        - 0-255.bin
    - unknown_chunk
    """
    #
    # ** input

    input_file = tmp_path / "input-file"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("empty.txt", data=b"")
        zf.writestr("0-255.bin", data=bytes(range(256)))

    # entropy is calculated in 1Kb blocks for files smaller than 80Kb
    # so let's have 1 block with 0 entropy, 1 with 6 bit entropy, the rest with 8 bit entropy
    unknown_chunk_content = (
        bytes(1024) + bytes(range(64)) * 4 * 4 + bytes(range(256)) * 4 * 62
    )
    with input_file.open("ab") as f:
        f.write(unknown_chunk_content)

    config = ExtractionConfig(
        extract_root=tmp_path / "extract_root",
        randomness_depth=100,
        randomness_plot=True,
        handlers=(handlers.archive.zip.ZIPHandler,),
    )

    # ** action

    process_result = process_file(config, input_file)

    task_result_by_name = {r.task.path.name: r for r in process_result.results}

    def get_all(file_name, report_type: type[ReportType]) -> list[ReportType]:
        return task_result_by_name[file_name].filter_reports(report_type)

    # ** verification

    # the unknown chunk report for the second chunk for the input file should have a randomness report
    # with a percentages (scaled up bits) of 64 items, for 0, 6, 8, 8, ... bits of entropies
    [unknown_chunk_report] = get_all("input-file", UnknownChunkReport)
    unknown_randomness = unknown_chunk_report.randomness
    assert (
        unknown_randomness is not None
    )  # removes pyright complaints for the below lines :(
    assert unknown_randomness.shannon.percentages == [0.0, 75.0] + [100.0] * 62
    assert unknown_randomness.shannon.block_size == 1024
    assert round(unknown_randomness.shannon.mean, 2) == 98.05  # noqa: PLR2004
    assert unknown_randomness.shannon.highest == 100.0  # noqa: PLR2004
    assert unknown_randomness.shannon.lowest == 0.0
    assert unknown_randomness.chi_square.percentages == [0.0, 0.0] + [100.0] * 62
    assert unknown_randomness.chi_square.block_size == 1024
    assert round(unknown_randomness.shannon.mean, 2) == 98.05  # noqa: PLR2004
    assert unknown_randomness.chi_square.highest == 100.0  # noqa: PLR2004
    assert unknown_randomness.chi_square.lowest == 0.0

    # we should have randomness calculated for files without extractions, except for empty files
    assert get_all("empty.txt", RandomnessReport) == []
    assert [
        RandomnessReport(
            shannon=RandomnessMeasurements(
                percentages=[100.0], block_size=1024, mean=100.0
            ),
            chi_square=RandomnessMeasurements(
                percentages=[100.0], block_size=1024, mean=100.0
            ),
        )
    ] == get_all("0-255.bin", RandomnessReport)


@pytest.mark.parametrize(
    "skip_extraction, file_count, extracted_file_count",
    [
        (True, 5, 0),
        (False, 5, 6),
    ],
)
def test_skip_extraction(
    skip_extraction: bool,
    file_count: int,
    extracted_file_count: int,
    tmp_path: Path,
    extraction_config: ExtractionConfig,
):
    input_file = tmp_path / "input"
    with zipfile.ZipFile(input_file, "w") as zf:
        for i in range(file_count):
            zf.writestr(f"file{i}", data=b"This is a test file.")

    extraction_config.extract_root = tmp_path / "output"
    extraction_config.skip_extraction = skip_extraction

    process_result = process_file(extraction_config, input_file)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    assert len(task_result_by_path) == extracted_file_count + 1
    assert (
        len(list(extraction_config.extract_root.rglob("**/*"))) == extracted_file_count
    )


class ConcatenateExtractor(DirectoryExtractor):
    def extract(self, paths: list[Path], outdir: Path):
        outfile = outdir / "data"
        with outfile.open("wb") as f:
            for path in paths:
                if path.is_file():
                    f.write(path.read_bytes())


class FailDirExtractor(DirectoryExtractor):
    def extract(self, paths: list[Path], outdir: Path):
        del paths
        del outdir
        raise ValueError


class SplitDirHandler(DirectoryHandler):
    NAME = "split"
    PATTERN = Glob("*.part0")
    EXTRACTOR = ConcatenateExtractor()

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        return MultiFile(
            name=file.name[:-6], paths=sorted(file.parent.glob(f"{file.name[:-1]}*"))
        )


class NoExtractionSplitDirHandler(SplitDirHandler):
    NAME = "no-extract-split"

    EXTRACTOR = None


class ExtractionFailSplitDirHandler(SplitDirHandler):
    NAME = "split-fail"

    EXTRACTOR = FailDirExtractor()


class SpecialDirHandler(DirectoryHandler):
    NAME = "special"
    PATTERN = SingleFile("special")
    EXTRACTOR = ConcatenateExtractor()

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        return MultiFile(name="special", paths=sorted(file.parent.glob("special*")))


class MultiLevelSplitDirHandler(DirectoryHandler):
    NAME = "multi-level-split"
    PATTERN = Glob("*.parts")
    EXTRACTOR = ConcatenateExtractor()

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        return MultiFile(
            name=file.name[:-6],
            paths=[file, *sorted(file.parent.glob(f"{file.name}/*"))],
        )


class ExceptionDirHandler(SplitDirHandler):
    NAME = "exception-handler"
    PATTERN = Glob("*.part0")
    EXTRACTOR = None

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        del file
        raise ValueError("Something bad happened")


class DummyTestHandler(Handler):
    NAME = "dummy"
    PATTERNS = [Regex("AA")]
    EXTRACTOR = Command("cp", "{inpath}", "{outdir}/AA")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        del file
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 1)


@pytest.fixture
def multi_volume_zip(tmp_path: Path):
    input_file = tmp_path / "input"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("test.part0", data=b"AA")
        zf.writestr("test.part1", data=b"BB")
        zf.writestr("test.part2", data=b"CC")
        zf.writestr("test2.part0", data=b"DD")
        zf.writestr("test2.part1", data=b"EE")
        zf.writestr("other", data=b"AA")
    return input_file


@pytest.fixture
def extraction_root(tmp_path: Path):
    return tmp_path / "extract_root"


@pytest.fixture
def multi_file_extraction_config(extraction_root: Path):
    return ExtractionConfig(
        extract_root=extraction_root,
        randomness_depth=0,
        handlers=(handlers.archive.zip.ZIPHandler, DummyTestHandler),
        dir_handlers=(SplitDirHandler,),
    )


def test_multi_file_processing(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)

    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"
    files1 = [
        directory / "test.part0",
        directory / "test.part1",
        directory / "test.part2",
    ]
    files2 = [directory / "test2.part0", directory / "test2.part1"]

    out1 = directory / "test_extract" / "data"
    out2 = directory / "test2_extract" / "data"
    other_out = directory / "other_extract" / "0-1.dummy_extract" / "AA"

    assert out1.read_bytes() == b"AABBCC"
    assert out2.read_bytes() == b"DDEE"

    assert other_out.read_bytes() == b"A"

    multi_file_reports = task_result_by_path[directory].filter_reports(MultiFileReport)
    assert len(multi_file_reports) == 2
    assert {report.id for report in multi_file_reports} == {
        task_result_by_path[out1].task.blob_id,
        task_result_by_path[out2].task.blob_id,
    }
    assert {path for report in multi_file_reports for path in report.paths} == set(
        files1
    ) | set(files2)


def test_multi_file_extracted_files_processing(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    data = extraction_root / "input_extract" / "test_extract" / "data"

    out = (
        extraction_root
        / "input_extract"
        / "test_extract"
        / "data_extract"
        / "0-1.dummy_extract"
        / "AA"
    )

    assert out.read_bytes() == b"A"

    assert len(task_result_by_path[data].subtasks) == 1
    assert task_result_by_path[data].subtasks[0] == task_result_by_path[out.parent].task
    chunk_reports = task_result_by_path[data].filter_reports(ChunkReport)
    assert len(chunk_reports) == 1
    assert task_result_by_path[out.parent].task.blob_id == chunk_reports[0].id


def test_multi_file_content_not_processed(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    out = extraction_root / "input_extract" / "test.part0"
    extract_dir = extraction_root / "input_extract" / "test.part0_extract"

    assert not extract_dir.exists()
    assert not task_result_by_path[out].subtasks


def test_multi_file_paths_kept_and_have_reports(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    parts = [
        extraction_root / "input_extract" / "test.part0",
        extraction_root / "input_extract" / "test.part1",
        extraction_root / "input_extract" / "test.part2",
    ]

    for part in parts:
        assert part.exists()
        assert task_result_by_path[part].reports
        assert task_result_by_path[part].filter_reports(HashReport)
        assert task_result_by_path[part].filter_reports(StatReport)
        assert task_result_by_path[part].filter_reports(FileMagicReport)


def test_multi_file_no_extraction(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    multi_file_extraction_config.dir_handlers = (NoExtractionSplitDirHandler,)
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"
    extract_dir = extraction_root / "input_extract" / "test_extract"

    assert not extract_dir.exists()
    assert task_result_by_path[directory].filter_reports(MultiFileReport)


def test_multi_file_multi_level_content(
    tmp_path: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    input_file = tmp_path / "input"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("test.parts/0", data=b"AA")
        zf.writestr("test.parts/1", data=b"BB")

    multi_file_extraction_config.dir_handlers = (MultiLevelSplitDirHandler,)
    process_result = process_file(multi_file_extraction_config, input_file)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"
    parts = [
        directory / "test.parts",
        directory / "test.parts" / "0",
        directory / "test.parts" / "1",
    ]

    extract_dir = extraction_root / "input_extract" / "test_extract"
    data = extract_dir / "data"

    assert extract_dir.exists()
    assert data.exists()
    assert data.read_bytes() == b"AABB"

    multi_file_reports = task_result_by_path[directory].filter_reports(MultiFileReport)
    assert multi_file_reports
    assert multi_file_reports[0].id == task_result_by_path[data].task.blob_id
    assert set(multi_file_reports[0].paths) == set(parts)

    for part in parts:
        assert task_result_by_path[part].reports
        assert task_result_by_path[part].filter_reports(StatReport)

        if not part.is_dir():
            assert task_result_by_path[part].filter_reports(HashReport)
            assert task_result_by_path[part].filter_reports(FileMagicReport)
            assert not task_result_by_path[part].subtasks
            part_extract = part.parent / f"{part.name}_extract"
            assert not part_extract.exists()


def test_multi_file_collide(
    tmp_path: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    input_file = tmp_path / "input"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("special", data=b"AA")
        zf.writestr("special.part0", data=b"BB")
        zf.writestr("special.part1", data=b"C")

    multi_file_extraction_config.dir_handlers = (SpecialDirHandler, SplitDirHandler)
    process_result = process_file(multi_file_extraction_config, input_file)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"
    files = {directory / "special.part0", directory / "special.part1"}

    collision_reports = task_result_by_path[directory].filter_reports(
        MultiFileCollisionReport
    )
    assert collision_reports
    assert collision_reports[0].paths == files


def test_multi_file_extract_dir(
    tmp_path: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    input_file = tmp_path / "input"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("test_extract", data=b"XXXX")
        zf.writestr("test.part0", data=b"BB")
        zf.writestr("test.part1", data=b"C")

    process_result = process_file(multi_file_extraction_config, input_file)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"

    multi_file_reports = task_result_by_path[directory].filter_reports(MultiFileReport)
    assert multi_file_reports
    assert any(
        isinstance(report, OutputDirectoryExistsReport)
        for report in multi_file_reports[0].extraction_reports
    )


def test_multi_file_extraction_failed(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    multi_file_extraction_config.dir_handlers = (ExtractionFailSplitDirHandler,)
    process_result = process_file(multi_file_extraction_config, multi_volume_zip)
    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"

    multi_file_reports = task_result_by_path[directory].filter_reports(MultiFileReport)
    assert multi_file_reports
    assert all(
        isinstance(extraction_report, UnknownError)
        for report in multi_file_reports
        for extraction_report in report.extraction_reports
    )


def test_multi_file_calculate_exception(
    multi_volume_zip: Path,
    multi_file_extraction_config: ExtractionConfig,
    extraction_root: Path,
):
    multi_file_extraction_config.dir_handlers = (ExceptionDirHandler,)
    multi_file_extraction_config.handlers = (handlers.archive.zip.ZIPHandler,)

    process_result = process_file(multi_file_extraction_config, multi_volume_zip)

    task_result_by_path = {r.task.path: r for r in process_result.results}

    directory = extraction_root / "input_extract"

    multi_file_reports = task_result_by_path[directory].filter_reports(MultiFileReport)
    assert not multi_file_reports
    assert (directory / "test.part0") in task_result_by_path
    assert (directory / "test.part1") in task_result_by_path
    assert (directory / "test.part2") in task_result_by_path
    assert (directory / "test2.part0") in task_result_by_path
    assert (directory / "test2.part1") in task_result_by_path
    assert (directory / "other") in task_result_by_path
