import logging
from pathlib import Path
from typing import Any

import structlog
from dissect.cstruct import Instance, dumpstruct


def format_hex(value: int):
    return f"0x{value:x}"


class noformat:
    """Keep the value from formatting,
    even if it would match one of the types in pretty_print_types processor.
    """

    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value


def _format_message(value: Any, extract_root: Path) -> Any:
    if isinstance(value, noformat):
        return value.get()

    elif isinstance(value, Path):
        try:
            return str(value.relative_to(extract_root))
        except ValueError:
            # original files given to unblob may not be relative to extract_root
            return str(value)

    elif isinstance(value, Instance):
        return dumpstruct(value, output="string")

    elif isinstance(value, int):
        return format_hex(value)

    return value


def pretty_print_types(extract_root: Path):
    def convert_type(logger, method_name: str, event_dict: structlog.types.EventDict):
        for key, value in event_dict.items():
            event_dict[key] = _format_message(value, extract_root)

        return event_dict

    return convert_type


def configure_logger(verbose: bool, extract_root: Path):
    if structlog.is_configured:
        # If used as a library, with already configured structlog, we still need our types to be prettyly printed
        processors = structlog.get_config().get("processors", [])
        processors.insert(0, pretty_print_types(extract_root))
        structlog.configure(processors=processors)
        return

    log_level = logging.DEBUG if verbose else logging.INFO
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(
            key="timestamp", fmt="%Y-%m-%d %H:%M.%S", utc=True
        ),
        pretty_print_types(extract_root),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ]

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        processors=processors,
        cache_logger_on_first_use=True,
    )
