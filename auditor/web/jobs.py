"""The job store: one upload, one directory, one inventory.

A job is deliberately the dullest thing that satisfies the requirement -- a
directory named by a server-generated id, holding the configs that were
uploaded, the inventory JSON that ingesting them produced, and any PDFs that
have been asked for since.  There is no database, no ORM and no migration
system, because none of those would make a hackathon demo more convincing and
all of them would make it harder to reason about where an uploaded file went.

Disk is the source of truth and memory is only a cache, which is what makes the
store restartable: ``inventory.json`` is written with the same
:func:`auditor.ingest.write_inventory` the CLI uses and read back with the same
:func:`auditor.ingest.read_inventory`, so a server that restarts mid-demo still
serves every job it already accepted.  Round-tripping through the published
contract rather than through a private pickle is also a standing check that the
contract really is complete.

Job directories live under the system temp directory by default -- never inside
the repository tree.  Uploaded configurations are somebody's live network
topology; they are not something to scatter through a git checkout.
"""

import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..ingest import read_inventory, write_inventory
from ..models.inventory import DeviceInventory

#: Job ids are generated here and never accepted from a client as a path
#: component without passing this first. Thirty-two hex characters, which is
#: what ``uuid4().hex`` produces and what nothing containing a path separator,
#: a dot or a wildcard can ever match.
JOB_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")

CONFIG_DIRNAME = "configs"
PDF_DIRNAME = "pdfs"
INVENTORY_FILENAME = "inventory.json"


def is_valid_job_id(job_id: str) -> bool:
    """Whether a client-supplied string is shaped like an id this server issued."""
    return bool(JOB_ID_PATTERN.match(job_id))


@dataclass
class Job:
    """One upload and everything derived from it."""

    job_id: str
    root: Path
    inventory: DeviceInventory

    @property
    def config_dir(self) -> Path:
        return self.root / CONFIG_DIRNAME

    @property
    def pdf_dir(self) -> Path:
        return self.root / PDF_DIRNAME

    @property
    def inventory_path(self) -> Path:
        return self.root / INVENTORY_FILENAME

    def device_at(self, index: int):
        """The record at an index, or ``None`` -- never an exception to catch.

        The index *is* the device id in this API. Inventory order is
        deterministic by construction (``ingest`` sorts before it runs) and a
        job's inventory never changes after it is created, so position is a
        stable identifier for the life of the job. It is also an integer, which
        means the device id can no more traverse a path than the job id can.
        """
        if index < 0 or index >= len(self.inventory.devices):
            return None
        return self.inventory.devices[index]


class JobStore:
    """Creates, remembers and re-reads jobs.

    Not thread-safe by design of the surrounding demo: uvicorn serves this from
    one event loop, job ids are unique, and jobs are immutable once written. The
    only mutable state is the cache, and losing a cache entry costs one read.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else Path(tempfile.gettempdir()) / "netaudit-web"
        self.root.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Job] = {}

    # -- creation -----------------------------------------------------------

    def new_job_dir(self) -> tuple:
        """Allocate an id and its directories, before anything is uploaded.

        Split out from :meth:`record` so uploads land in the job directory from
        the very first byte. Nothing is ever written to a shared staging area
        and moved: a file that exists briefly outside its sandbox has, briefly,
        escaped it.
        """
        job_id = uuid.uuid4().hex
        root = self.root / job_id
        (root / CONFIG_DIRNAME).mkdir(parents=True, exist_ok=True)
        (root / PDF_DIRNAME).mkdir(parents=True, exist_ok=True)
        return job_id, root

    def record(self, job_id: str, root: Path, inventory: DeviceInventory) -> Job:
        """Persist the inventory for a job and cache it."""
        job = Job(job_id=job_id, root=root, inventory=inventory)
        write_inventory(inventory, job.inventory_path)
        self._cache[job_id] = job
        return job

    # -- lookup -------------------------------------------------------------

    def get(self, job_id: str) -> Optional[Job]:
        """Fetch a job by id, reading it back from disk if it is not cached.

        Returns ``None`` for an unknown *or* malformed id. Validating the shape
        here rather than at each call site is what guarantees no route can turn
        a client string into a directory traversal by forgetting a check.
        """
        if not is_valid_job_id(job_id):
            return None
        if job_id in self._cache:
            return self._cache[job_id]

        root = self.root / job_id
        inventory_path = root / INVENTORY_FILENAME
        if not inventory_path.is_file():
            return None
        try:
            inventory = read_inventory(inventory_path)
        except (OSError, ValueError):
            return None

        job = Job(job_id=job_id, root=root, inventory=inventory)
        self._cache[job_id] = job
        return job

    def job_ids(self) -> List[str]:
        """Every job currently on disk, newest directory last."""
        if not self.root.is_dir():
            return []
        return sorted(
            path.name
            for path in self.root.iterdir()
            if path.is_dir() and is_valid_job_id(path.name) and (path / INVENTORY_FILENAME).is_file()
        )

    # -- teardown -----------------------------------------------------------

    def discard(self, job_id: str) -> bool:
        """Delete one job's directory. Used by tests; harmless in a demo."""
        if not is_valid_job_id(job_id):
            return False
        self._cache.pop(job_id, None)
        root = self.root / job_id
        if not root.is_dir():
            return False
        shutil.rmtree(root, ignore_errors=True)
        return True


__all__ = ["Job", "JobStore", "is_valid_job_id"]
