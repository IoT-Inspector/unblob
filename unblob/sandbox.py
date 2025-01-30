import ctypes
import sys
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Callable, Optional, TypeVar

from structlog import get_logger
from unblob_native.sandbox import (
    AccessFS,
    SandboxError,
    restrict_access,
)

if sys.version_info >= (3, 10):
    from typing import ParamSpec
else:
    from typing_extensions import ParamSpec

from unblob.processing import ExtractionConfig

logger = get_logger()

P = ParamSpec("P")
R = TypeVar("R")


class Sandbox:
    """Configures restricted file-systems to run functions in.

    When calling ``run()``, a separate thread will be configured with
    minimum required file-system permissions. All subprocesses spawned
    from that thread will honor the restrictions.
    """

    def __init__(
        self,
        config: ExtractionConfig,
        log_path: Path,
        report_file: Optional[Path],
        extra_passthrough: Iterable[AccessFS] = (),
    ):
        self.passthrough = [
            # Python, shared libraries, extractor binaries and so on
            AccessFS.read("/"),
            # Multiprocessing
            AccessFS.read_write("/dev/shm"),  # noqa: S108
            # Extracted contents
            AccessFS.read_write(config.extract_root),
            AccessFS.remove_dir(config.extract_root),
            AccessFS.remove_file(config.extract_root),
            AccessFS.make_dir(config.extract_root.parent),
            AccessFS.read_write(log_path),
            *extra_passthrough,
        ]

        if report_file:
            self.passthrough += [
                AccessFS.read_write(report_file),
                AccessFS.make_reg(report_file.parent),
            ]

    def run(self, callback: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
        """Run callback with restricted filesystem access."""
        exception = None
        result = None

        def _run_in_thread(callback, *args, **kwargs):
            nonlocal exception, result

            self._try_enter_sandbox()
            try:
                result = callback(*args, **kwargs)
            except BaseException as e:
                exception = e

        thread = threading.Thread(
            target=_run_in_thread, args=(callback, *args), kwargs=kwargs
        )
        thread.start()

        try:
            thread.join()
        except KeyboardInterrupt:
            raise_in_thread(thread, KeyboardInterrupt)
            thread.join()

        if exception:
            raise exception  # pyright: ignore[reportGeneralTypeIssues]
        return result  # pyright: ignore[reportReturnType]

    def _try_enter_sandbox(self):
        try:
            restrict_access(*self.passthrough)
        except SandboxError:
            logger.warning(
                "Sandboxing FS access is unavailable on this system, skipping."
            )


def raise_in_thread(thread: threading.Thread, exctype: type) -> None:
    if thread.ident is None:
        raise RuntimeError("Thread is not started")

    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_ulong(thread.ident), ctypes.py_object(exctype)
    )

    # success
    if res == 1:
        return

    # Need to revert the call to restore interpreter state
    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread.ident), None)

    # Thread could have exited since
    if res == 0:
        return

    # Something bad have happened
    raise RuntimeError("Could not raise exception in thread", thread.ident)
