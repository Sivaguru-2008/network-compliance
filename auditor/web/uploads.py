"""Turning an untrusted multipart upload into a file safely on disk.

Everything a client sends is hostile until proven otherwise, and the client
filename is the most hostile part of it: it is attacker-chosen text that a naive
server joins straight onto a path.  So it is never used as a write target here.
The name that reaches the filesystem is *generated* -- an index this server
assigned, plus a sanitized echo of the original kept only so an operator can
recognise their own file in the results.

Three independent layers stand between the request and the disk, in this order:

1. **Reject** a filename that carries a path at all -- a separator, a ``..``
   segment, a drive letter. A browser file picker never produces one, so the
   only thing that does is someone probing.
2. **Sanitize** whatever survives down to ``[A-Za-z0-9._-]`` and prefix the
   index, so two uploads named ``config.conf`` cannot overwrite each other.
3. **Verify containment** of the resolved path inside the job directory
   immediately before opening it, so even a bug in layers 1 and 2 cannot write
   outside the sandbox.

Size is enforced *while streaming*, never after: a cap checked once the file is
already buffered is not a cap, it is a description of what you accepted.
"""

import re
from pathlib import Path
from typing import Optional

from ..ingest import CONFIG_SUFFIXES

#: Per-file ceiling. A network configuration is text; the largest real ones run
#: to a few megabytes of a chassis switch with a thousand interfaces. Two is
#: generous for that and nowhere near enough to be interesting as a disk filler.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Ceiling across one request, so a caller cannot walk past ``MAX_FILE_BYTES``
#: simply by sending more parts.
MAX_REQUEST_BYTES = 64 * 1024 * 1024

#: Cap on parts per request. A fleet upload is large; an unbounded one is a
#: denial-of-service with a friendly filename.
MAX_FILES = 200

#: How much of the original filename is echoed back into the stored name.
MAX_NAME_LENGTH = 96

#: Extensions accepted from the web. The empty suffix is allowed because plenty
#: of real exports have none; anything outside this set is refused by name
#: rather than sniffed, since guessing at content type is how you end up
#: accepting an archive that unpacks somewhere unfortunate.
ALLOWED_SUFFIXES = frozenset(CONFIG_SUFFIXES) | {""}

#: Read granularity for the streaming copy.
CHUNK_BYTES = 64 * 1024

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_PATHISH = re.compile(r"[/\\]")
_DRIVE = re.compile(r"^[A-Za-z]:")


class UploadRejected(Exception):
    """An upload was refused before anything was written.

    Carries the operator-facing reason: a rejection that does not say which file
    was refused, or why, just looks like the tool is broken.
    """

    def __init__(self, detail: str, *, filename: Optional[str] = None) -> None:
        self.detail = detail
        self.filename = filename
        super().__init__(detail)


def reject_pathish_filename(filename: str) -> None:
    """Refuse a client filename that describes a location rather than a name.

    Sanitizing these would also be safe, but silence is the wrong response to a
    request that had to be constructed deliberately. ``../../etc/passwd`` is not
    a typo, and answering it with a stored file called ``passwd`` tells the
    sender their probe was interesting.
    """
    if _PATHISH.search(filename):
        raise UploadRejected(
            f"Filename may not contain a path separator: {filename!r}",
            filename=filename,
        )
    if ".." in filename:
        raise UploadRejected(
            f"Filename may not contain a parent-directory segment: {filename!r}",
            filename=filename,
        )
    if filename.strip() in ("", "."):
        raise UploadRejected(f"Invalid filename: {filename!r}", filename=filename)
    # "C:config.conf" is a drive-relative path on Windows, not a filename.
    if _DRIVE.match(filename):
        raise UploadRejected(
            f"Filename may not contain a drive letter: {filename!r}", filename=filename
        )


def check_suffix(filename: str) -> None:
    """Type-limit by extension, and say what would have been accepted."""
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        accepted = ", ".join(sorted(s for s in ALLOWED_SUFFIXES if s))
        raise UploadRejected(
            f"Unsupported file type {suffix!r} for {filename!r}. "
            f"Configuration files are expected to be one of: {accepted} (or no extension).",
            filename=filename,
        )


def sanitize_filename(filename: str, index: int) -> str:
    """Generate the on-disk name. The client's version is an echo, not a source.

    The index prefix is what actually guarantees uniqueness and safety: it makes
    the name this server's decision, defuses Windows reserved device names
    (``CON`` becomes ``0003_CON``), and keeps two files called ``switch.conf``
    from becoming one. Sorted order of these names is upload order, which is
    what makes the inventory come back in the order the operator sent.
    """
    stem = _PATHISH.split(filename)[-1] if filename else ""
    stem = _UNSAFE.sub("_", stem).strip("._-")
    stem = stem[:MAX_NAME_LENGTH]
    if not stem:
        stem = "upload"
    return f"{index:04d}_{stem}"


def resolve_within(directory: Path, name: str) -> Path:
    """Final containment check, done on the resolved path just before writing.

    Layers 1 and 2 should already make this unreachable. It is here because
    "should" is not a security property, and the cost of being wrong is a write
    outside the sandbox.
    """
    root = directory.resolve()
    candidate = (root / name).resolve()
    if root not in candidate.parents:
        raise UploadRejected(f"Refusing to write outside the job directory: {name!r}")
    return candidate


async def save_upload(
    upload,
    directory: Path,
    index: int,
    *,
    budget_remaining: int,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> Path:
    """Stream one uploaded part to disk under a generated name.

    Returns the path written. Raises :class:`UploadRejected` -- having removed
    any partial file -- if the part exceeds either the per-file cap or what is
    left of the request budget. The partial is removed because a rejected upload
    that leaves half a config behind would be ingested on the next pass as a
    truncated device.
    """
    original = upload.filename or ""
    reject_pathish_filename(original)
    check_suffix(original)

    destination = resolve_within(directory, sanitize_filename(original, index))

    written = 0
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = await upload.read(CHUNK_BYTES)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_file_bytes:
                    raise UploadRejected(
                        f"{original!r} exceeds the {max_file_bytes // (1024 * 1024)} MB "
                        "per-file limit.",
                        filename=original,
                    )
                if written > budget_remaining:
                    raise UploadRejected(
                        f"Upload exceeds the {MAX_REQUEST_BYTES // (1024 * 1024)} MB "
                        "total request limit.",
                        filename=original,
                    )
                handle.write(chunk)
    except UploadRejected:
        destination.unlink(missing_ok=True)
        raise

    return destination


__all__ = [
    "ALLOWED_SUFFIXES",
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_REQUEST_BYTES",
    "UploadRejected",
    "check_suffix",
    "reject_pathish_filename",
    "resolve_within",
    "sanitize_filename",
    "save_upload",
]
