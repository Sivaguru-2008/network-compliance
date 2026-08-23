"""``python -m auditor.training`` — the loop's own command, separate from the audit CLI."""

from .cli import main

if __name__ == "__main__":
    main()
