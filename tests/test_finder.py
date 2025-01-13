import attrs
import pytest
from pyperscan import Scan

from unblob.file_utils import DEFAULT_BUFSIZE, InvalidInputFormat
from unblob.finder import build_hyperscan_database, search_chunks
from unblob.models import File, Handler, HexString, Regex, ValidChunk
from unblob.parser import InvalidHexString


class TestHandlerA(Handler):
    NAME = "handlerA"
    PATTERNS = [Regex("A")]

    def calculate_chunk(self, file, start_offset: int):
        del file  # unused argument
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 5)


class TestHandlerB(Handler):
    NAME = "handlerB"
    PATTERNS = [Regex("BB"), Regex("BC")]

    PATTERN_MATCH_OFFSET = -1

    def calculate_chunk(self, file, start_offset: int):
        del file  # unused argument
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 10)


class TestHandlerD(Handler):
    NAME = "handlerD"
    PATTERNS = [Regex("D"), HexString("ff ff ff")]

    def calculate_chunk(self, file, start_offset: int):
        del file, start_offset  # unused arguments


class TestHandlerEof(Handler):
    NAME = "handlerEOF"
    PATTERNS = [Regex("EOF")]

    def calculate_chunk(self, file, start_offset: int):
        del file, start_offset  # unused arguments
        raise EOFError


class TestHandlerInvalid(Handler):
    NAME = "handlerInvalid"
    PATTERNS = [Regex("I")]

    def calculate_chunk(self, file, start_offset: int):
        del file, start_offset  # unused arguments
        raise InvalidInputFormat


class TestHandlerExc(Handler):
    NAME = "handlerEXC"
    PATTERNS = [Regex("EXC")]

    def calculate_chunk(self, file, start_offset: int):
        del file, start_offset  # unused arguments
        raise ValueError("Error")


class TestHandlerL(Handler):
    NAME = "handlerL"
    PATTERNS = [Regex("L")]

    def calculate_chunk(self, file, start_offset: int):
        del file  # unused argument
        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + DEFAULT_BUFSIZE * 2
        )


def test_build_hyperscan_database():
    db = build_hyperscan_database((TestHandlerA, TestHandlerB))
    matches = []

    def on_match(m, pattern_id, start, end):
        m.append((pattern_id, start, end))
        return Scan.Continue

    db.build(matches, on_match).scan(b"A123456789BB")  # type: ignore

    assert len(matches) == 2
    assert matches[0][1] == 0
    assert matches[1][1] == 10


def test_db_and_handler_map_instances_are_cached():
    db1 = build_hyperscan_database((TestHandlerA, TestHandlerB))
    db2 = build_hyperscan_database((TestHandlerA, TestHandlerB))
    db3 = build_hyperscan_database((TestHandlerA,))
    assert db1 is db2
    assert db1 is not db3


def test_invalid_hexstring_pattern_raises():
    class InvalidHandler(Handler):
        NAME = "InvalidHandler"
        PATTERNS = [HexString("invalid pattern")]

        def calculate_chunk(self, file, start_offset: int):
            pass

    with pytest.raises(InvalidHexString):
        build_hyperscan_database((TestHandlerA, TestHandlerB, InvalidHandler))


@pytest.mark.parametrize(
    "content, expected_chunks",
    [
        pytest.param(
            b"00A23450", [ValidChunk(start_offset=2, end_offset=7)], id="single-chunk"
        ),
        pytest.param(
            b"0BB34A678900",
            [ValidChunk(start_offset=0, end_offset=10)],
            id="chunk-with-relative-match-offset",
        ),
        pytest.param(
            b"A23450BB3456789",
            [
                ValidChunk(start_offset=0, end_offset=5),
                ValidChunk(start_offset=5, end_offset=15),
            ],
            id="multiple-chunk",
        ),
        pytest.param(
            b"0BC34A67890",
            [ValidChunk(start_offset=0, end_offset=10)],
            id="inner-chunk-ignored",
        ),
        pytest.param(
            b"0BC34A67890A2345",
            [
                ValidChunk(start_offset=0, end_offset=10),
                ValidChunk(start_offset=11, end_offset=16),
            ],
            id="inner-chunk-ignored-scan-continues",
        ),
        pytest.param(
            b"A23450BB34",
            [ValidChunk(start_offset=0, end_offset=5)],
            id="overflowing-chunk-ignored",
        ),
        pytest.param(
            b"0BBA2345",
            [ValidChunk(start_offset=3, end_offset=8)],
            id="overflowing-chunk-ignored-scan-continues",
        ),
        pytest.param(
            b"A2345", [ValidChunk(start_offset=0, end_offset=5)], id="whole-file-chunk"
        ),
        pytest.param(
            b"00000A2345",
            [ValidChunk(start_offset=5, end_offset=10)],
            id="chunk-till-end-of-file",
        ),
        pytest.param(
            b"BB34A678900",
            [ValidChunk(start_offset=4, end_offset=9)],
            id="chunk-with-invalid-relative-match-offset-ignored",
        ),
        pytest.param(
            b"00D00A2345",
            [ValidChunk(start_offset=5, end_offset=10)],
            id="invalid-chunk-ignored",
        ),
        pytest.param(
            b"EOFA2345",
            [ValidChunk(start_offset=3, end_offset=8)],
            id="eof-ignored-scan-continues",
        ),
        pytest.param(
            b"IA2345",
            [ValidChunk(start_offset=1, end_offset=6)],
            id="invalid-chunk-ignored-scan-continues",
        ),
        pytest.param(
            b"EXCA2345",
            [ValidChunk(start_offset=3, end_offset=8)],
            id="exception-ignored-scan-continues",
        ),
        pytest.param(b"0", [], id="1-byte"),
        pytest.param(b"1234567890", [], id="no-chunk"),
        pytest.param(
            b"A2345L1" + b"1" * DEFAULT_BUFSIZE * 2,
            [
                ValidChunk(start_offset=0, end_offset=5),
                ValidChunk(start_offset=5, end_offset=5 + DEFAULT_BUFSIZE * 2),
            ],
            id="multi-large-chunk",
        ),
        pytest.param(
            b"L" + b"1" * DEFAULT_BUFSIZE + b"A2345" + b"1" * DEFAULT_BUFSIZE,
            [ValidChunk(start_offset=0, end_offset=DEFAULT_BUFSIZE * 2)],
            id="large-small-inside-ignored",
        ),
        pytest.param(
            b"0123456789L" + b"1" * DEFAULT_BUFSIZE + b"A2345" + b"1" * DEFAULT_BUFSIZE,
            [ValidChunk(start_offset=10, end_offset=10 + DEFAULT_BUFSIZE * 2)],
            id="padding-large-small-inside-ignored",
        ),
        pytest.param(
            b"L" + b"1" * (DEFAULT_BUFSIZE * 2 - 1) + b"A2345" + b"1" * DEFAULT_BUFSIZE,
            [
                ValidChunk(start_offset=0, end_offset=DEFAULT_BUFSIZE * 2),
                ValidChunk(
                    start_offset=DEFAULT_BUFSIZE * 2, end_offset=DEFAULT_BUFSIZE * 2 + 5
                ),
            ],
            id="large-small",
        ),
    ],
)
def test_search_chunks(content, expected_chunks, task_result):
    file = File.from_bytes(content)

    handlers = (
        TestHandlerA,
        TestHandlerB,
        TestHandlerD,
        TestHandlerEof,
        TestHandlerInvalid,
        TestHandlerExc,
        TestHandlerL,
    )

    chunks = search_chunks(file, len(content), handlers, task_result)

    assert len(chunks) == len(expected_chunks)
    for expected_chunk, chunk in zip(expected_chunks, chunks):
        assert attrs.evolve(chunk, id="") == attrs.evolve(expected_chunk, id="")
