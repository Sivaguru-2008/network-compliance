"""The web dashboard: a presentation shell over the same core the CLI drives.

Nothing in this package parses a configuration, evaluates a control, or draws a
PDF.  It accepts uploads, hands them to :func:`auditor.ingest.ingest_paths` --
the exact function the CLI's ``--bulk`` path calls -- and serves back the
resulting :class:`~auditor.models.inventory.DeviceInventory` and the Step 9 PDF
that :func:`auditor.report.write_device_pdf` renders.

The dependency direction is one-way and load-bearing: ``web`` imports the core,
the core never imports ``web``.  That is what keeps the CLI a peer frontend
rather than a second engine, and what lets this whole package be deleted without
the auditor losing a single capability.

``app`` is imported lazily so that ``import auditor.web`` costs nothing on a
machine with no FastAPI installed -- the same courtesy the LLM parser and the
PDF renderer extend for their own optional dependencies.
"""

from typing import Any

__all__ = ["app", "create_app"]


def __getattr__(name: str) -> Any:  # pragma: no cover - trivial lazy re-export
    if name in __all__:
        from . import app as _app_module

        return getattr(_app_module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
