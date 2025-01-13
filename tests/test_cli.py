from collections.abc import Iterable
from pathlib import Path
from typing import Optional
from unittest import mock

import pytest
from click.testing import CliRunner

import unblob.cli
from unblob.extractors import Command
from unblob.extractors.command import MultiFileCommand
from unblob.handlers import BUILTIN_HANDLERS
from unblob.models import DirectoryHandler, Glob, Handler, HexString, MultiFile
from unblob.processing import (
    DEFAULT_DEPTH,
    DEFAULT_PROCESS_NUM,
    DEFAULT_SKIP_EXTENSION,
    DEFAULT_SKIP_MAGIC,
    ExtractionConfig,
)
from unblob.testing import is_sandbox_available
from unblob.ui import (
    NullProgressReporter,
    ProgressReporter,
    RichConsoleProgressReporter,
)


class TestHandler(Handler):
    NAME = "test_handler"
    PATTERNS = [HexString("21 3C")]
    EXTRACTOR = Command("testcommand", "for", "test", "handler")

    def calculate_chunk(self, *args, **kwargs):
        pass


class ExistingCommandHandler(TestHandler):
    EXTRACTOR = Command("sh", "something")


class TestDirHandler(DirectoryHandler):
    NAME = "test_dir_handler"
    PATTERN = Glob("*.test")
    EXTRACTOR = MultiFileCommand("test-multi", "for", "test", "handler")

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        pass


class ExistingCommandDirHandler(TestDirHandler):
    EXTRACTOR = MultiFileCommand("true")


def test_show_external_dependencies_missing():
    handlers = (ExistingCommandHandler, TestHandler)
    runner = CliRunner()
    result = runner.invoke(
        unblob.cli.cli,
        ["--show-external-dependencies"],
        handlers=handlers,
        dir_handlers=(TestDirHandler,),
    )
    assert result.exit_code == 1
    assert (
        result.output
        == """The following executables found installed, which are needed by unblob:
    sh             ✓
    test-multi     ✗
    testcommand    ✗
"""
    )


def test_show_external_dependencies_exists():
    handlers = (ExistingCommandHandler, ExistingCommandHandler)
    runner = CliRunner()
    result = runner.invoke(
        unblob.cli.cli,
        ["--show-external-dependencies"],
        handlers=handlers,
        dir_handlers=(ExistingCommandDirHandler,),
    )
    assert result.exit_code == 0
    assert (
        result.output
        == """The following executables found installed, which are needed by unblob:
    sh      ✓
    true    ✓
"""
    )


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(["--help"], id="alone"),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
                "--help",
                "tests",
            ],
            id="eager_1",
        ),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
                "tests",
                "--help",
            ],
            id="eager_2",
        ),
    ],
)
def test_help(params):
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, params)
    assert result.exit_code == 0
    # NOTE: In practice, it writes "Usage: unblob ...", this is done in the `cli.main` with `click.make_context`
    assert result.output.startswith("Usage: cli [OPTIONS] FILE")


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(["-v"], id="v"),
        pytest.param(["--verbose"], id="verbose"),
        pytest.param(["-e", "unblob"], id="e"),
        pytest.param(["--extract-dir", "unblob"], id="extract-dir"),
        pytest.param(["-d", "2"], id="d"),
        pytest.param(["--depth", "2"], id="depth"),
        pytest.param(["-p", "2"], id="p"),
        pytest.param(["--process-num", "2"], id="process-num"),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
            ],
            id="verbose+extract-dir+depth+process-num",
        ),
    ],
)
def test_without_file(params: list[str]):
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, params)
    assert result.exit_code == 2
    assert "Missing argument 'FILE'" in result.output


def test_non_existing_file(tmp_path: Path):
    runner = CliRunner()
    path = Path("non/existing/path/54")
    result = runner.invoke(unblob.cli.cli, ["--extract-dir", str(tmp_path), str(path)])
    assert result.exit_code == 2
    assert "Invalid value for 'FILE'" in result.output
    assert f"File '{path}' does not exist" in result.output


def test_dir_for_file(tmp_path: Path):
    runner = CliRunner()
    out_path = tmp_path.joinpath("out")
    out_path.mkdir()
    in_path = tmp_path.joinpath("in")
    in_path.mkdir()
    result = runner.invoke(
        unblob.cli.cli, ["--extract-dir", str(out_path), str(in_path)]
    )
    assert result.exit_code != 0


@pytest.mark.parametrize(
    "params, expected_depth, expected_randomness_depth, expected_process_num, expected_verbosity, expected_progress_reporter",
    [
        pytest.param(
            [],
            DEFAULT_DEPTH,
            1,
            DEFAULT_PROCESS_NUM,
            0,
            RichConsoleProgressReporter,
            id="empty",
        ),
        pytest.param(
            ["--verbose"],
            DEFAULT_DEPTH,
            1,
            DEFAULT_PROCESS_NUM,
            1,
            NullProgressReporter,
            id="verbose-1",
        ),
        pytest.param(
            ["-vv"],
            DEFAULT_DEPTH,
            1,
            DEFAULT_PROCESS_NUM,
            2,
            NullProgressReporter,
            id="verbose-2",
        ),
        pytest.param(
            ["-vvv"],
            DEFAULT_DEPTH,
            1,
            DEFAULT_PROCESS_NUM,
            3,
            NullProgressReporter,
            id="verbose-3",
        ),
        pytest.param(
            ["--depth", "2"], 2, 1, DEFAULT_PROCESS_NUM, 0, mock.ANY, id="depth"
        ),
        pytest.param(
            ["--process-num", "2"], DEFAULT_DEPTH, 1, 2, 0, mock.ANY, id="process-num"
        ),
    ],
)
def test_archive_success(
    params,
    expected_depth: int,
    expected_randomness_depth: int,
    expected_process_num: int,
    expected_verbosity: int,
    expected_progress_reporter: type[ProgressReporter],
    tmp_path: Path,
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__"
        / "apple.zip"
    )
    process_file_mock = mock.MagicMock()
    logger_config_mock = mock.MagicMock()
    new_params = [*params, "--extract-dir", str(tmp_path), str(in_path)]
    with (
        mock.patch.object(unblob.cli, "process_file", process_file_mock),
        mock.patch.object(unblob.cli, "configure_logger", logger_config_mock),
    ):
        result = runner.invoke(unblob.cli.cli, new_params)
    assert result.exit_code == 0
    assert "error" not in result.output
    assert "warning" not in result.output
    log_path = Path("unblob.log")
    config = ExtractionConfig(
        extract_root=tmp_path,
        max_depth=expected_depth,
        randomness_depth=expected_randomness_depth,
        randomness_plot=bool(expected_verbosity >= 3),
        process_num=expected_process_num,
        handlers=BUILTIN_HANDLERS,
        verbose=expected_verbosity,
        progress_reporter=expected_progress_reporter,
    )
    process_file_mock.assert_called_once_with(config, in_path, None)
    logger_config_mock.assert_called_once_with(expected_verbosity, tmp_path, log_path)


@pytest.mark.parametrize(
    "args, keep_extracted_chunks, fail_message",
    [
        ([], False, "Should *NOT* have kept extracted chunks"),
        (["-k"], True, "Should have kept extracted chunks"),
        (["--keep-extracted-chunks"], True, "Should have kept extracted chunks"),
    ],
)
def test_keep_extracted_chunks(
    args: list[str], keep_extracted_chunks: bool, fail_message: str, tmp_path: Path
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__"
        / "apple.zip"
    )
    params = [*args, "--extract-dir", str(tmp_path), str(in_path)]

    process_file_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(unblob.cli.cli, params)

    assert result.exit_code == 0
    process_file_mock.assert_called_once()
    assert (
        process_file_mock.call_args.args[0].keep_extracted_chunks
        == keep_extracted_chunks
    ), fail_message


@pytest.mark.parametrize(
    "skip_extension, expected_skip_extensions",
    [
        pytest.param((), DEFAULT_SKIP_EXTENSION, id="skip-extension-empty"),
        pytest.param(("",), ("",), id="skip-zip-extension-empty-suffix"),
        pytest.param((".zip",), (".zip",), id="skip-extension-zip"),
        pytest.param((".rlib",), (".rlib",), id="skip-extension-rlib"),
    ],
)
def test_skip_extension(
    skip_extension: list[str], expected_skip_extensions: tuple[str, ...], tmp_path: Path
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__"
        / "apple.zip"
    )
    args = []
    for suffix in skip_extension:
        args += ["--skip-extension", suffix]
    params = [*args, "--extract-dir", str(tmp_path), str(in_path)]
    process_file_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(unblob.cli.cli, params)
    assert (
        process_file_mock.call_args.args[0].skip_extension == expected_skip_extensions
    )
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "args, skip_extraction, fail_message",
    [
        ([], False, "Should *NOT* have skipped extraction"),
        (["-s"], True, "Should have skipped extraction"),
        (["--skip-extraction"], True, "Should have skipped extraction"),
    ],
)
def test_skip_extraction(
    args: list[str], skip_extraction: bool, fail_message: str, tmp_path: Path
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__"
        / "apple.zip"
    )
    params = [*args, "--extract-dir", str(tmp_path), str(in_path)]

    process_file_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(unblob.cli.cli, params)

    assert result.exit_code == 0
    process_file_mock.assert_called_once()
    assert process_file_mock.call_args.args[0].skip_extraction == skip_extraction, (
        fail_message
    )


@pytest.mark.parametrize(
    "args, skip_magic, fail_message",
    [
        ([], DEFAULT_SKIP_MAGIC, "Should have kept default skip magics"),
        (
            ["--skip-magic", "SUPERMAGIC"],
            (*DEFAULT_SKIP_MAGIC, "SUPERMAGIC"),
            "Should have kept default skip magics",
        ),
        (["--clear-skip-magics"], [], "Should have cleared default skip magics"),
        (
            ["--clear-skip-magics", "--skip-magic", "SUPERMAGIC"],
            ["SUPERMAGIC"],
            "Should have cleared default skip magics",
        ),
        (
            ["--clear-skip-magics", "--skip-magic", DEFAULT_SKIP_MAGIC[1]],
            [DEFAULT_SKIP_MAGIC[1]],
            "Should allow user specified and remove the rest",
        ),
    ],
)
def test_clear_skip_magics(
    args: list[str], skip_magic: Iterable[str], fail_message: str, tmp_path: Path
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__"
        / "apple.zip"
    )
    params = [*args, "--extract-dir", str(tmp_path), str(in_path)]

    process_file_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(unblob.cli.cli, params)

    assert result.exit_code == 0
    process_file_mock.assert_called_once()
    assert sorted(process_file_mock.call_args.args[0].skip_magic) == sorted(
        skip_magic
    ), fail_message


@pytest.mark.skipif(
    not is_sandbox_available(), reason="Sandboxing is only available on Linux"
)
def test_sandbox_escape(tmp_path: Path):
    runner = CliRunner()

    in_path = tmp_path / "input"
    in_path.touch()
    extract_dir = tmp_path / "extract-dir"
    params = ["--extract-dir", str(extract_dir), str(in_path)]

    unrelated_file = tmp_path / "unrelated"

    process_file_mock = mock.MagicMock(
        side_effect=lambda *_args, **_kwargs: unrelated_file.write_text(
            "sandbox escape"
        )
    )
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(unblob.cli.cli, params)

    assert result.exit_code != 0
    assert isinstance(result.exception, PermissionError)
    process_file_mock.assert_called_once()
