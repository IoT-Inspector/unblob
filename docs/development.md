---
hide:
  - navigation
---

# Development

Want to contribute to unblob? That's great! We developed a framework
(we sometimes reference it as _"unblob core"_), to make it very **easy**
to add **support for new file formats**. This page describes the process
of how to do that.

If you _don't want or don't know_ how to develop complex Python applications,
that's not a problem! If there is a format you would like to be supported in
unblob and you can _describe and explain_ it (maybe with nifty
hex-representations, hand-drawings or smoke signs, or whatever you cup-of-tea
is), we might help you implement it! Just open a
[new ticket](https://github.com/onekey-sec/unblob/issues/new)
in the GitHub issue tracker.

If you do know all this stuff, and you have all the tools in the world installed,
you can just jump to the [How to write handlers](#writing-handlers) section
where the exciting stuff is.

## Setting up development environment

### Required tools

- **Python**: unblob requires **Python 3.9** or above. Make sure that
  [Python is installed](https://www.python.org/downloads/) on your system.

- **git**: You need it for cloning the repository.
  Install it [from the git-scm website](https://git-scm.com/download).

- **uv**: it is a package manager for Python dependencies. Follow the instructions on the
  [uv website](https://docs.astral.sh/uv/getting-started/installation/) to install the latest version.

- **pre-commit**: We are using [pre-commit](https://pre-commit.com/) to run
  checks like linters, type checks and formatting issues.

- **Git LFS**: We have big integration test files, and we are using Git LFS to track them.
  [Install `git-lfs`](https://git-lfs.github.com/) from the website.

- **Rust** (_for unblob-native_): unblob has a [Rust extension](https://github.com/onekey-sec/unblob-native) for
  performance intensive processing. Building it is entirely optional and requires [`rustup`](https://rustup.rs/) to be
  installed on the host system. Follow the instructions on the [rustup website](https://rustup.rs/) to install it.

- **pyenv** (_Recommended_): When you are working with multiple versions of Python,
  pyenv makes it very easy to install and use different versions and make virtualenvs.
  Follow the [instructions on GitHub](https://github.com/pyenv/pyenv) for the installation.
  If your system already has at least Python 3.9 installed, you don't need it.

### Cloning the Git repository

Set up your git config, fork the project on GitHub, then clone your fork locally.

If you installed `pre-commit`, you can run `pre-commit install`, which makes pre-commit run automatically during git commits with git hooks, so you don't have to run them manually.

You need to setup Git LFS once, before you will be able to run the whole test suite:

    git lfs install

!!! Warning

    If you have cloned the repository prior to installing Git LFS, you need to run
    the following commands in the cloned repository once:

        git lfs pull
        git lfs checkout

### Making a virtualenv

The recommended way to develop Python projects in a semi-isolated way is to use `virtualenv`.

If you don't want to manage it separately, you can rely on `uv` to automatically
create a virtualenv for you on install.

Or instead of uv you can use `pyenv`. You can set the Python interpreter
version for the local folder only with:

```
pyenv local 3.12.7
```

### Installing Python dependencies

We are using [uv](https://docs.astral.sh/uv/) to manage our Python
dependencies. To install all required dependencies for development, you can run
the following command:

```
uv install
```

Please note that it installs dependencies within the dedicated virtual
environment. So if you want to run `unblob` or `pytest`, you need to do it from
within the virtual environment:

Using uv run:

```
uv run unblob
uv run pytest tests -v
```

By dropping into the virtual environment:

```
uv run $SHELL
unblob
pytest tests -v
```

### Running pre-commit

If you installed the `pre-commit` git hook when setting up your local git repo, you
don't need this step, otherwise you can run all checks with `pre-commit run --all-files`.

### Running the tests

We are using [pytest](https://docs.pytest.org/) for running our test suite.  
We have big integration files in the `tests/integration` directory,
we are using [Git LFS to track them](https://git-lfs.github.com/).  
Only after you [installed Git LFS](#cloning-the-git-repository), can you
run all tests, with `python -m pytest tests/` in the activated virtualenv.

## Writing handlers

Every handler inherits from the abstract class `Handler` located in
[unblob/models.py](https://github.com/onekey-sec/unblob/blob/main/unblob/models.py):

```python
class Handler(abc.ABC):
    """A file type handler is responsible for searching, validating and "unblobbing" files from Blobs."""
    NAME: str
    PATTERNS: str
    PATTERN_MATCH_OFFSET: int = 0
    EXTRACTOR: Optional[Extractor]

    @classmethod
    def get_dependencies(cls):
        """Returns external command dependencies needed for this handler to work."""

    @abc.abstractmethod
    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> Optional[ValidChunk]:
        """Returns a ValidChunk when it found a valid format for this Handler.
        Otherwise it can raise and Exception or return None, those will be ignored.
        """

    def extract(self, inpath: Path, outdir: Path):
        """Responsible for extraction a ValidChunk."""
```

- `NAME`: a unique name for this handler, this value will be appended at the end of carved out chunks
- `PATTERNS`: an array of `Hyperscan` rules.
- `PATTERN_MATCH_OFFSET`: an offset from the `hyperscan` match to the actual start offset.  
  This happens when the magic is not the first field in a file header
- `EXTRACTOR`: an optional [Extractor](extractors.md). It can be set to `None`
  if the handler is supposed to only carve files
- `get_dependencies()`: returns the extractor dependencies. This helps unblob keep
  track of [third party dependencies](extractors.md).
- `calculate_chunk()`: this is the method that needs to be overridden in your
  handler. It receives a `file` object and the effective `start_offset` of your
  chunk. This is where you implement the logic to compute the `end_offset` and
  return a `ValidChunk` object.

### StructHandler class

`StructHandler` is a specialized subclass of `Handler` that provides a structure
parsing API based on the [`dissect.cstruct`](https://pypi.org/project/dissect.cstruct/) library:

```python
class StructHandler(Handler):
    C_DEFINITIONS: str
    HEADER_STRUCT: str

    def __init__(self):
        self._struct_parser = StructParser(self.C_DEFINITIONS)

    @property
    def cparser_le(self):
        return self._struct_parser.cparser_le

    @property
    def cparser_be(self):
        return self._struct_parser.cparser_be

    def parse_header(self, file: io.BufferedIOBase, endian=Endian.LITTLE):
        header = self._struct_parser.parse(self.HEADER_STRUCT, file, endian)
        logger.debug("Header parsed", header=header, _verbosity=3)
        return header
```

This class defines new attributes and methods:

- `C_DEFINITIONS`: a string holding one or multiple structures definitions in C,
  which will be used to parse the format. We use the following standard to define structs:

        typedef struct my_struct {
            uint8 header_length;
        } my_struct_t;

- `HEADER_STRUCT`: the name of your C structure that you'll use to parse the format header.
- `parse_header()`: it will parse the file from the current offset in `endian`
  endianness into a structure using `HEADER_STRUCT` defined in `C_DEFINITIONS`.

If you need to parse structure using different endianness, the class exposes two properties:

- `cparser_le`: `dissect.cstruct` parser configured in little endian
- `cparser_be`: `dissect.cstruct` parser configured in big endian

!!! Recommendation

    If your format allows it, we strongly recommend you to inherit from the
    StructHandler given that it will be strongly typed and less prone to errors.

### DirectoryHandler class

`DirectoryHandler` is a specialized handler responsible for identifying multi-file formats
located in a directory or in a subtree. The abstract class is located in
[unblob/models.py](https://github.com/onekey-sec/unblob/blob/main/unblob/models.py):

```python
class DirectoryHandler(abc.ABC):
    """A directory type handler is responsible for searching, validating and "unblobbing" files from multiple files in a directory."""

    NAME: str

    EXTRACTOR: DirectoryExtractor

    PATTERN: DirectoryPattern

    @classmethod
    def get_dependencies(cls):
        """Return external command dependencies needed for this handler to work."""
        if cls.EXTRACTOR:
            return cls.EXTRACTOR.get_dependencies()
        return []

    @abc.abstractmethod
    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        """Calculate the MultiFile in a directory, using a file matched by the pattern as a starting point."""

    def extract(self, paths: List[Path], outdir: Path):
        if self.EXTRACTOR is None:
            logger.debug("Skipping file: no extractor.", paths=paths)
            raise ExtractError

        # We only extract every blob once, it's a mistake to extract the same blob again
        outdir.mkdir(parents=True, exist_ok=False)

        self.EXTRACTOR.extract(paths, outdir)
```

- `NAME`: a unique name for this handler
- `PATTERN`: A `DirectoryPattern` used to identify a starting/main file of the given format.
- `EXTRACTOR`: a [DirectoryExtractor](extractors.md).
- `get_dependencies()`: returns the extractor dependencies. This helps unblob keep
  track of [third party dependencies](extractors.md).
- `calculate_multifile()`: this is the method that needs to be overridden in your
  handler. It receives a `file` Path object identified by the `PATTERN` in the directory.
  This is where you implement the logic to compute and return the `MultiFile` file set.

Any files that are being processed as part of a `MultiFile` set would be skipped from `Chunk`
detection.

Any file that is part of multiple `MultiFile` is a collision and results in a processing error.

### Example Handler implementation

Let's imagine that we have a custom file format that always starts with the
magic: `UNBLOB!!`, followed by the size of the file (header included) as an
unsigned 32 bit integer.

First, we create a file in `unblob/handlers/archive/myformat.py` and write the
skeleton of our handler:

```python
class MyformatHandler(StructHandler):
    NAME = "myformat"

    PATTERNS = []
    C_DEFINITIONS = ""
    HEADER_STRUCT = ""
    EXTRACTOR = None

    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> Optional[ValidChunk]:
        return
```

We need to match on our custom magic. To find the right offset, we need to match
on the `UNBLOB!!` byte pattern, so we add a `HexString` Hyperscan rule:

```python hl_lines="4-6"
class MyformatHandler(StructHandler):
    NAME = "myformat"

    PATTERNS = [
        HexString("55 4E 42 4C 4F 42 21 21"),  # "UNBLOB!!"
    ]

    C_DEFINITIONS = ""
    HEADER_STRUCT = ""
    EXTRACTOR = None

    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> Optional[ValidChunk]:
        return
```

Then we need to parse the header, so we define a C structure in `C_DEFINITIONS` and adapt `HEADER_STRUCT` accordingly:

```py hl_lines="8-14"
class MyformatHandler(StructHandler):
    NAME = "myformat"

    PATTERNS = [
        HexString("55 4E 42 4C 4F 42 21 21"),  # "UNBLOB!!"
    ]

    C_DEFINITIONS= r"""
        typedef struct myformat_header {
            char magic[8];
            uint32 size;
        } myformat_header_t;
    """
    HEADER_STRUCT= "myformat_header_t"

    EXTRACTOR = None

    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> Optional[ValidChunk]:
        return
```

With everything set, all that is left is to implement the `calculate_chunk` function:

```python hl_lines="18-21"
class MyformatHandler(StructHandler):
    NAME = "myformat"

    PATTERNS = [
        HexString("55 4E 42 4C 4F 42 21 21"),  # "UNBLOB!!"
    ]

    C_DEFINITIONS= r"""
        typedef struct myformat_header {
            char magic[8];
            uint32 size;
        } myformat_header_t;
    """
    HEADER_STRUCT= "myformat_header_t"

    EXTRACTOR = None

    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.LITTLE)
        end_offset = start_offset + header.size
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
```

**That's it!**  
Now you have a working handler for your own custom format!

### Testing Handlers

If you want to submit a new format handler to unblob, it needs to come up with
its own set of integration tests.

We've implemented integration tests this way:

1. pytest picks up integration test files corresponding to your handler in
   `test/integration/type/handler_name/__input__` directory.
2. pytest runs unblob on all the integration test files it picked up in the first step.
3. pytest runs `diff` between the temporary extraction directory and
   `test/integration/type/handler_name/__output__`.
4. if no differences are observed the test pass, otherwise it fails.

!!! Important

    Create integration test files that cover **all the possible scenarios of the target format**.

    That includes different endianness, different versions, different padding, different algorithms. An excellent example of this is the integration test files for JFFS2 filesystems where we have filesystems covering both endianness (big endian, little endian), with or without padding, and with different compression algorithms (no compression, zlib, rtime, lzo):

    ```
    ./fruits.new.be.zlib.padded.jffs2
    ./fruits.new.be.nocomp.padded.jffs2
    ./fruits.new.be.rtime.jffs2
    ./fruits.new.le.lzo.jffs2
    ./fruits.new.le.rtime.jffs2
    ./fruits.new.le.nocomp.padded.jffs2
    ./fruits.new.be.rtime.padded.jffs2
    ./fruits.new.be.lzo.jffs2
    ./fruits.new.be.zlib.jffs2
    ./fruits.new.le.zlib.padded.jffs2
    ./fruits.new.be.lzo.padded.jffs2
    ./fruits.new.le.lzo.padded.jffs2
    ./fruits.new.be.nocomp.jffs2
    ./fruits.new.le.zlib.jffs2
    ./fruits.new.le.rtime.padded.jffs2
    ./fruits.new.le.nocomp.jffs2
    ```

### Utilities Functions

We developed a bunch of utility functions which helped us during the development of
existing unblob handlers. Do not hesitate to take a look at them in
[unblob/file_utils.py](https://github.com/onekey-sec/unblob/blob/main/unblob/file_utils.py)
to see if any of those functions could help you during your own handler
development.

### Hyperscan Rules

Our hyperscan-based implementation accepts two different kinds of rule
definitions: `Regex` and `HexString`.

#### Regex

This object simply represents any regular expression. Example:

```python
PATTERNS = [
    Regex(r"-lh0-")
]
```

#### HexString

This object can be used to write rules using the same DSL as Yara. The only
limitation is that we do not support multi-line comments and unbounded jumps.
Here's an example of a Hyperscan rule based on `HexString`:

```python
PATTERNS = [
    HexString("""
        // this is a comment
        AA 00 [2] 01
    """)
]
```

In addition, start and end of input anchors (`^` and `$` like in regular
expressions) can also be used to restrict a match to the beginning or the end of
the input file.

### DirectoryPatterns

The `DirectoryHandler` uses these patterns to identify the starting/main file of a given
multi-file format. There are currently two main types: `Glob` and `SingleFile`

#### Glob

The `Glob` object can use traditional globbing to detect files in a directory. This could be used when
the file could have a varying part. There are cases where multiple multi-file set could be in a single
directory. The job of the `DirectoryPattern` is to recognize the main file for each set.

Here is an example on `Glob`:

```python
PATTERN = Glob("*.7z.001")
```

This example identify the first volume of a multi-volume sevenzip archive. Notice that this could pick
up all first volumes in a given directory. (NB: Detecting the other volumes of a given set is the
responsibility of the `DirectoryHandler.calculate_multifile` function. Do not write a `Glob` which picks
up all the files of a multi-file set as that would result in errors.)


#### SingleFile

The `SingleFile` object can be used to identify a single file with a known name. (Obviously only use this if the
main file name is well-known and does not have a varying part. It also means that only a single multi-file set
can be detected in a given directory.)

Here is an example on `SingleFile`:

```python
PATTERN = SingleFile("meta-data.json")
```

This would pick up the file `meta-data.json` and pass it to the `DirectoryHandler`. The handler still has to
verify the file and has to find the additional files.

## Writing extractors

!!! Recommendation

    We support custom Python based extractors as part of unblob, but unless you
    write a handler for an exotic format, you should check if the
    [Command extractor](#command-extractor) is sufficient for your needs, as
    it's very simple to use.

### Command extractor

This extractor simply runs a command line tool on the carved-out file (`inpath`)
to extract into the extraction directory (`outdir`). Below is the `Command`
extractor instance of the ZIP handler:

```python
EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")
```

If you have a custom format with no supported command to extract it, check out
the `Extractor` Python class.

### Extractor class

The `Extractor` interface is defined in
[unblob/models.py](https://github.com/onekey-sec/unblob/blob/main/unblob/models.py):

```python
class Extractor(abc.ABC):
    def get_dependencies(self) -> List[str]:
        """Returns the external command dependencies."""
        return []

    @abc.abstractmethod
    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        """Extract the carved out chunk. Raises ExtractError on failure."""
```

Two methods are exposed by this class:

- `get_dependencies()`: you should override it if your custom extractor relies on
  external dependencies such as command line tools
- `extract()`: you must override this function. This is where you'll perform the
  extraction of `inpath` content into `outdir` extraction directory

!!! Recommendation

    Although it is possible to implement `extract()` with path manipulations,
    checks for path traversals, and performing io by using Python libraries
    (`os`, `pathlib.Path`), but it turns out somewhat tedious.
    Instead we recommend to remove boilerplate and use a helper class `FileSystem` from
    [unblob/file_utils.py](https://github.com/onekey-sec/unblob/blob/main/unblob/file_utils.py)
    which ensures that all file objects are created under its root.

### DirectoryExtractor class

The `DirectoryExtractor` interface is defined in
[unblob/models.py](https://github.com/onekey-sec/unblob/blob/main/unblob/models.py):

```python
class DirectoryExtractor(abc.ABC):
    def get_dependencies(self) -> List[str]:
        """Return the external command dependencies."""
        return []

    @abc.abstractmethod
    def extract(self, paths: List[Path], outdir: Path) -> Optional[ExtractResult]:
        """Extract from a multi file path list.

        Raises ExtractError on failure.
        """
```

Two methods are exposed by this class:

- `get_dependencies()`: you should override it if your custom extractor relies on
  external dependencies such as command line tools
- `extract()`: you must override this function. This is where you'll perform the
  extraction of `paths` files into `outdir` extraction directory

!!! Recommendation

    Similarly to `Extractor`, it is recommended to use the `FileSystem` helper class to
    implement `extract`.

### Example Extractor

Extractors are quite complex beasts, so rather than trying to come up with a
fake example, we recommend you to read through our
[RomFS extractor](https://github.com/onekey-sec/unblob/blob/868da1b53412e4f1fedaa3da72fab0852330a83e/unblob/handlers/filesystem/romfs.py#L305-L313)
code to see what it looks like in real world applications.

## Guidelines

### Code style

We adhere to PEP8 and enforce proper formatting of source files using [ruff
format](https://docs.astral.sh/ruff/formatter/) so you should not worry about
formatting source code at all, `pre-commit` will take care of it.

For linting we use [ruff check](https://docs.astral.sh/ruff/linter/). Lint
errors can be shown in your editor of choice by one of the [editor
plugins](https://docs.astral.sh/ruff/editors/).

### File Format Correctness

We want to strike the right balance between false positive reduction and a
totally loose implementation. We tend _not to validate checksums_ in order to
still be able to _extract corrupted content_. However, if the lack of checksum
validation gets in the way by leaving the handler generating a large amount of
false positive, then it's time to revisit the handler and implement stronger
header checks.

### Common unblob Handler Mistakes

This is a collection of all the bad code we've seen during unblob development.
Learn from us so you can avoid them in the future 🙂

- Use `seek` rather than `read` whenever possible, it's [faster](https://github.com/onekey-sec/unblob/pulls?q=is%3Apr+is%3Aclose+%22seek+rather+%22).
- You should always keep in mind to `seek` to the position the header starts or make sure you are always at the correct
  offset at all times. For example we made the mistake multiple times that read 4 bytes for file magic and didn't seek
  back.
- Watch out for [negative seeking](https://github.com/onekey-sec/unblob/pull/280)
- Make sure you get your types right! signedness can [get in the way](https://github.com/onekey-sec/unblob/pull/130).
- Try to use as specific as possible patterns to identify data in Handlers to avoid false-positive matches
  and extra processing in the Handler.
- Try to avoid using overlapping patterns, as patterns that match on the same data could easily collide. Hyperscan
  does not guarantee priority between patterns matching on the same data. (Hyperscan reports matches ordered by the
  pattern match end offset. In case multiple pattern match on the same end offset the matching order depends on the
  pattern registration order which is undefined in unblob.)
