# unblob

unblob is a tool for getting information out of any kind of binary blob.

## Quickstart

### Using from Docker container

Unblob can be used right away from a `docker` container: \
`ghcr.io/iot-inspector/unblob:latest`

The `--pull always` option is recommended, because the project is currently under heavy development, so we expect frequent changes.


```shell
docker run \
  --rm \
  --pull always \
  -v /path/to/out/dir/on/host:/data/output \
  -v /path/to/input/files/on/host:/data/input \
ghcr.io/iot-inspector/unblob:latest /data/input/path/to/file
```

Help on usage:
```shell
docker run --rm --pull always ghcr.io/iot-inspector/unblob:latest --help
```

### Using as a library

```python
from pathlib import Path
import unblob

files = Path("/path/to/input/file")
# or with multiple files
files = (
  Path("/path/to/input/file/1"),
  Path("/path/to/input/file/2"),
)
extract_root = Path("/path/to/out/dir")
# optional parameters
depth = 5
verbose = True

return_code = unblob.unblob(
  files=files,
  extract_root=extract_root,
  depth=depth,
  verbose=verbose
)
print(f"return_code: {return_code}")
```
## Development

### Dependencies

We are using [poetry](https://python-poetry.org/) for managing dependencies.

`poetry install` will install all required dependencies in a virtualenv.

### Testing

We are using pytest for running our test suite.\
We have big integration files in the `tests/integration` directory,
we are using [Git LFS to track them](https://git-lfs.github.com/).
You need to install Git LFS first to be able to run the whole test suite:

```console
$ sudo apt install git-lfs
$ git lfs install
```

After you installed Git LFS, you can run all tests, with
`python -m pytest tests/` in the activated virtualenv.

### Linting

We are using [pre-commit](https://pre-commit.com/) for running checks.
Important commands:

- `pre-commit install` makes the pre-commit run automatically
  during git commits with git hooks.
- `pre-commit run --all-files` runs the pre-commit for everything.
