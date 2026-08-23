"""The set of configurations the loop learns from.

A corpus entry is *labelled* when some deterministic parser recognises it —
that is what makes ground truth free. Unlabelled entries (unknown vendors) are
still useful: they are where human adjudications accumulate, and they are the
only place the candidate parser's real target distribution lives.
"""

import hashlib
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Type

from pydantic import BaseModel, ConfigDict, Field

from ..parsers import registry
from ..parsers.base import VendorParser

DEFAULT_PATTERNS = ("*.conf", "*.cfg", "*.txt")


class CorpusEntry(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    path: Path
    text: str = Field(repr=False)
    sha256: str

    @property
    def name(self) -> str:
        return self.path.name

    def deterministic_parser(self, *, threshold: float = 0.3) -> Optional[Type[VendorParser]]:
        """The deterministic parser that claims this config, if any."""
        ranked = registry.rank(self.text)
        if not ranked:
            return None
        score, parser_cls = ranked[0]
        return parser_cls if score >= threshold else None

    @property
    def is_labelled(self) -> bool:
        return self.deterministic_parser() is not None


class ConfigCorpus(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    entries: List[CorpusEntry] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[CorpusEntry]:  # type: ignore[override]
        return iter(self.entries)

    @property
    def labelled(self) -> List[CorpusEntry]:
        """Entries a deterministic parser can produce ground truth for."""
        return [entry for entry in self.entries if entry.is_labelled]

    @property
    def unlabelled(self) -> List[CorpusEntry]:
        return [entry for entry in self.entries if not entry.is_labelled]

    @classmethod
    def from_paths(cls, paths: Sequence[Path], patterns: Sequence[str] = DEFAULT_PATTERNS) -> "ConfigCorpus":
        """Load configs from files and/or directories, deduplicated by content."""
        seen = set()
        entries: List[CorpusEntry] = []
        for candidate in _expand(paths, patterns):
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not text.strip():
                continue
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            if digest in seen:
                continue  # the same config under two names teaches nothing twice
            seen.add(digest)
            entries.append(CorpusEntry(path=candidate, text=text, sha256=digest))
        return cls(entries=sorted(entries, key=lambda e: str(e.path)))


def _expand(paths: Sequence[Path], patterns: Sequence[str]) -> Iterator[Path]:
    for path in paths:
        path = Path(path)
        if path.is_file():
            yield path
        elif path.is_dir():
            for pattern in patterns:
                yield from sorted(path.rglob(pattern))
