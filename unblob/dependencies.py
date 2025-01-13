import shutil

import attrs

from .models import DirectoryHandlers, Handlers


@attrs.define
class Dependency:
    command: str
    is_installed: bool


INSTALLED = "✓"
NOT_INSTALLED = "✗"


def get_dependencies(
    handlers: Handlers, dir_handlers: DirectoryHandlers
) -> list[Dependency]:
    all_commands = set()
    for handler in handlers:
        commands = handler.get_dependencies()
        all_commands.update(commands)
    for handler in dir_handlers:
        commands = handler.get_dependencies()
        all_commands.update(commands)
    rv = []
    for command in sorted(all_commands):
        is_installed = shutil.which(command) is not None
        rv.append(Dependency(command=command, is_installed=is_installed))
    return rv


def pretty_format_dependencies(dependencies: list[Dependency]) -> str:
    longest_key_length = max(len(dep.command) for dep in dependencies)
    lines = ["The following executables found installed, which are needed by unblob:"]
    for dependency in dependencies:
        mark = INSTALLED if dependency.is_installed else NOT_INSTALLED
        lines.append(f"    {dependency.command:<{longest_key_length}}    {mark}")
    return "\n".join(lines)
