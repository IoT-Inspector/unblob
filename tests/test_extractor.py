import io
from pathlib import Path, PosixPath

import pytest

from unblob.extractor import (
    carve_unknown_chunks,
    fix_extracted_directory,
    fix_permission,
    fix_symlink,
)
from unblob.models import TaskResult, UnknownChunk


class TestCarveUnknownChunks:
    def test_no_chunks(self, tmp_path: Path):
        test_file = io.BytesIO(b"some file")
        carve_unknown_chunks(tmp_path, test_file, [])
        assert list(tmp_path.iterdir()) == []

    def test_one_chunk(self, tmp_path: Path):
        content = b"test file"
        infile = tmp_path / "infile"
        infile.write_bytes(content)
        chunk = UnknownChunk(0, len(content))

        with infile.open("rb") as test_file:
            carve_unknown_chunks(tmp_path, test_file, [chunk])

        written_path = tmp_path / "0-9.unknown"
        assert set(tmp_path.iterdir()) == {infile, written_path}
        assert written_path.read_bytes() == content

    def test_multiple_chunks(self, tmp_path: Path):
        content = b"test file"
        infile = tmp_path / "infile"
        infile.write_bytes(content)
        chunks = [UnknownChunk(0, 4), UnknownChunk(4, 9)]

        with infile.open("rb") as test_file:
            carve_unknown_chunks(tmp_path, test_file, chunks)

        written_path1 = tmp_path / "0-4.unknown"
        written_path2 = tmp_path / "4-9.unknown"
        assert set(tmp_path.iterdir()) == {infile, written_path1, written_path2}
        assert written_path1.read_bytes() == content[:4]
        assert written_path2.read_bytes() == content[4:]


def test_fix_permission(tmpdir: Path):
    tmpdir = PosixPath(tmpdir)
    tmpfile = PosixPath(tmpdir / "file.txt")
    tmpfile.touch()
    tmpdir.chmod(0o777)
    tmpfile.chmod(0o777)
    fix_permission(tmpdir)
    fix_permission(tmpfile)
    assert (tmpdir.stat().st_mode & 0o777) == 0o775
    assert (tmpfile.stat().st_mode & 0o777) == 0o644


def test_fix_extracted_directory(tmpdir: Path):
    tmpdir = PosixPath(tmpdir)
    subdir = PosixPath(tmpdir / "testdir2")
    subdir.mkdir()
    tmpfile = PosixPath(subdir / "file.txt")
    tmpfile.touch()

    tmpfile.chmod(0o200)
    subdir.chmod(0o200)
    tmpdir.chmod(0o200)

    fix_extracted_directory(tmpdir, TaskResult())
    assert (tmpdir.stat().st_mode & 0o777) == 0o775
    assert (subdir.stat().st_mode & 0o777) == 0o775
    assert (tmpfile.stat().st_mode & 0o777) == 0o644


def test_fix_recursive_symlink(tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path("link_a")
    second_link_path = tmpdir / Path("link_b")
    link_path.symlink_to("link_b")
    second_link_path.symlink_to("link_a")

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.exists() is False


def test_fix_symlink_chain(tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path("link_a")

    target_path = Path(".")
    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.resolve() == tmpdir


def test_fix_symlink_chain_traversal(tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path("link_a")

    target_path = Path("..")
    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.exists() is False


@pytest.mark.parametrize(
    "link, target, expected",
    (
        ("link_a", "/etc/passwd", "etc/passwd"),
        ("link_b", "etc/passwd", "etc/passwd"),
        ("link_c", "target_c", "target_c"),
        ("link_d", "/tmp/out/test/../../target_d", "tmp/target_d"),
    ),
)
def test_fix_symlink(link: str, target: str, expected: str, tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path(link)
    expected_link = tmpdir / Path(expected)
    target_path = Path(target)

    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.resolve() == expected_link


@pytest.mark.parametrize(
    "link, target, expected",
    (
        ("dir_1/link_a", "../target_a", "../target_a"),
        ("dir_1/link_b", "target_b", "target_b"),
        ("dir_1/link_c", "../dir_1/target_c", "target_c"),
        ("dir_1/dir_2/link_d", "../../target_d", "../../target_d"),
        ("dir_1/dir_2/link_e", "../target_e", "../target_e"),
        ("dir_1/dir_2/dir_3/link_f", "../../../target_f", "../../../target_f"),
        ("dir_1/dir_2/dir_3/link_g", "../../dir_2/target_g", "../../dir_2/target_g"),
        ("dir_1/dir_2/dir_3/link_h", "../dir_1/target_h", "../dir_1/target_h"),
        ("dir_1/link_i", "/etc/passwd", "../etc/passwd"),
    ),
)
def test_fix_symlink_subdir(link: str, target: str, expected: str, tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path(link)
    expected_link = Path(expected)
    target_path = Path(target)

    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.resolve() == link_path.parent.joinpath(expected_link).resolve()


@pytest.mark.parametrize(
    "link, target",
    (
        ("link_a", "../target_a"),
        ("link_b", "../../target_b"),
        ("link_c", "../../../target_c"),
        ("link_d", "../../../../target_d"),
        ("link_e", "../../../../../target_e"),
        ("link_f", "/tmp/../../target_f"),
        ("link_g", "/tmp/out/../../../target_g"),
    ),
)
def test_fix_symlink_traversal(link: str, target: str, tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path(link)
    target_path = Path(target)

    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.exists() is False


@pytest.mark.parametrize(
    "link, target",
    (
        ("dir_1/link_a", "../../target_a"),
        ("dir_1/dir_2/link_b", "../../../target_b"),
        ("dir_1/dir_2/dir_3/link_f", "../../../../target_f"),
    ),
)
def test_fix_symlink_traversal_subdir(link: str, target: str, tmpdir: Path):

    tmpdir = PosixPath(tmpdir)
    link_path = tmpdir / Path(link)
    target_path = Path(target)

    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.symlink_to(target_path)

    fixed_link = fix_symlink(link_path, tmpdir, TaskResult())
    assert fixed_link.exists() is False
