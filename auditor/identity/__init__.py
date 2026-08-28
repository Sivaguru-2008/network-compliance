"""Device identity: who the device is, separate from how compliant it is."""

from .companion import (
    COMPANION_NOTE_PREFIX,
    COMPANION_SUFFIXES,
    companion_path,
    enrich_from_companion,
    is_companion_file,
    is_from_companion,
)
from .extractors import extract_identity, platform_key

__all__ = [
    "COMPANION_NOTE_PREFIX",
    "COMPANION_SUFFIXES",
    "companion_path",
    "enrich_from_companion",
    "extract_identity",
    "is_companion_file",
    "is_from_companion",
    "platform_key",
]
