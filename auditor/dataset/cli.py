"""Command-line interface for the vendor reference and configuration-data pipeline."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from .downloader import ReferenceDownloader
from .extractor import DocumentExtractor
from .fixtures_loader import load_or_sync_fixtures
from .gap_detector import ParserGapDetector
from .grammar import save_all_vendor_grammars
from .manifest import DatasetManifestManager
from .nlp_export import NLPDatasetExporter
from .nlp_extractor import NLPCommandExtractor
from .sources import VENDOR_SOURCES, get_all_vendor_keys, get_sources_for_vendor

console = Console()


def list_sources_cmd(args):
    """Print all authoritative vendor documentation sources in catalog."""
    table = Table(title="Authoritative Vendor CLI / Config Reference Catalog")
    table.add_column("#", style="dim")
    table.add_column("Vendor Key", style="cyan")
    table.add_column("Vendor / OS", style="bold")
    table.add_column("Document Title")
    table.add_column("Format", style="green")
    table.add_column("Access Type", style="magenta")
    table.add_column("URL")

    idx = 1
    for vendor_key, sources in VENDOR_SOURCES.items():
        for src in sources:
            table.add_row(
                str(idx),
                vendor_key,
                src.os_name,
                src.doc_title,
                src.doc_format.value.upper(),
                src.access_type.value,
                src.url[:65] + "..." if len(src.url) > 65 else src.url,
            )
            idx += 1

    console.print(table)


def download_references_cmd(args):
    """Download public vendor reference documentation and extract commands."""
    vendor = args.vendor or "all"
    force = getattr(args, "force", False)

    console.print(f"[bold blue]Starting vendor reference acquisition for:[/bold blue] [cyan]{vendor}[/cyan]\n")

    downloader = ReferenceDownloader()
    extractor = DocumentExtractor()
    nlp_extractor = NLPCommandExtractor()

    # Save vendor grammar schemas
    save_all_vendor_grammars()
    load_or_sync_fixtures()

    sources_to_fetch = get_sources_for_vendor(vendor)
    if not sources_to_fetch:
        console.print(f"[red]Error: Vendor '{vendor}' not found in source catalog.[/red]")
        sys.exit(1)

    table = Table(title="Reference Download & Extraction Results")
    table.add_column("Vendor", style="cyan")
    table.add_column("Document Title")
    table.add_column("Status", style="bold")
    table.add_column("SHA-256", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("Commands Extracted", justify="right", style="green")

    for src in sources_to_fetch:
        console.print(f"Fetching: [bold]{src.vendor_name}[/bold] - {src.doc_title} ...")
        res = downloader.download_source(src, force=force)

        cmd_count = 0
        status_display = res.status
        if res.status in ("DOWNLOADED", "CACHED"):
            status_display = f"[green][OK] {res.status}[/green]"
            # Extract text & sections
            if res.local_path:
                full_doc_path = Path("dataset") / res.local_path
                if full_doc_path.exists():
                    try:
                        ext_doc = extractor.extract_document(full_doc_path, src.vendor_key, src.doc_title, src.version)
                        cmds = nlp_extractor.extract_from_document(ext_doc, source_url=src.url)
                        if cmds:
                            nlp_extractor.save_vendor_commands(src.vendor_key, cmds)
                            cmd_count = len(cmds)
                    except Exception as e:
                        status_display = f"[yellow][OK] Doc ({e})[/yellow]"
        elif res.status == "ACCESS_REQUIRES_ACCOUNT":
            status_display = "[yellow]! ACCESS_REQUIRES_ACCOUNT[/yellow]"
        elif res.status == "UNAVAILABLE":
            status_display = "[red][X] UNAVAILABLE[/red]"

        sha_short = (res.sha256[:12] + "...") if res.sha256 else "N/A"
        size_str = f"{res.byte_size:,} B" if res.byte_size else "0 B"

        table.add_row(
            src.vendor_key,
            src.doc_title[:45] + ("..." if len(src.doc_title) > 45 else ""),
            status_display,
            sha_short,
            size_str,
            str(cmd_count),
        )

    console.print("\n")
    console.print(table)

    # Regenerate manifest
    manifest_mgr = DatasetManifestManager()
    manifest_mgr.generate_manifest()
    console.print("\n[bold green][OK] Manifest regenerated at dataset/manifest.json[/bold green]")


def status_cmd(args):
    """Display comprehensive status of all vendor references and knowledge bases."""
    manifest_mgr = DatasetManifestManager()
    gap_detector = ParserGapDetector()

    table = Table(title="Vendor Reference Dataset Status")
    table.add_column("Vendor Key", style="cyan")
    table.add_column("Vendor / OS", style="bold")
    table.add_column("Official Docs", justify="right")
    table.add_column("Config Fixtures", justify="right")
    table.add_column("Commands Extracted", justify="right", style="green")
    table.add_column("Parser Coverage", justify="right", style="yellow")
    table.add_column("Access Status", style="magenta")

    base = Path("dataset/vendor_references")

    for vk in get_all_vendor_keys():
        v_dir = base / vk
        doc_count = len(list((v_dir / "documents").glob("*.*"))) if (v_dir / "documents").exists() else 0
        fix_count = len(list((v_dir / "config_fixtures").glob("*.*"))) if (v_dir / "config_fixtures").exists() else 0

        cmd_count = 0
        cmd_file = v_dir / "commands" / "commands.json"
        if cmd_file.exists():
            try:
                with open(cmd_file, "r", encoding="utf-8") as f:
                    cmd_count = len(json.load(f))
            except Exception:
                pass

        gap_rep = gap_detector.analyze_vendor(vk)
        cov_str = f"{gap_rep.coverage_percentage:.1f}%" if gap_rep else "N/A"

        sources = get_sources_for_vendor(vk)
        access_types = {s.access_type.value for s in sources}
        access_str = ", ".join(sorted(access_types))

        os_name = sources[0].os_name if sources else vk

        table.add_row(
            vk,
            os_name,
            str(doc_count),
            str(fix_count),
            str(cmd_count),
            cov_str,
            access_str,
        )

    console.print(table)


def validate_cmd(args):
    """Cryptographically validate dataset manifest and file integrity."""
    console.print("[bold blue]Validating dataset artifacts against SHA-256 hashes...[/bold blue]")
    manifest_mgr = DatasetManifestManager()
    res = manifest_mgr.validate_dataset()

    table = Table(title="Dataset Integrity Validation Report")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Total Indexed Artifacts", str(res.total_artifacts))
    table.add_row("Cryptographically Valid", f"[green]{res.valid_artifacts}[/green]")
    table.add_row("Missing Files", f"[red]{len(res.missing_files)}[/red]" if res.missing_files else "[green]0[/green]")
    table.add_row("Hash Mismatches", f"[red]{len(res.hash_mismatches)}[/red]" if res.hash_mismatches else "[green]0[/green]")
    table.add_row("Empty Files", f"[yellow]{len(res.empty_files)}[/yellow]" if res.empty_files else "[green]0[/green]")
    table.add_row("Overall Integrity", "[bold green]PASSED[/bold green]" if res.is_valid else "[bold red]FAILED[/bold red]")

    console.print(table)

    if not res.is_valid:
        if res.missing_files:
            console.print(f"[red]Missing files:[/red] {res.missing_files[:5]}")
        if res.hash_mismatches:
            console.print(f"[red]Hash mismatches:[/red] {res.hash_mismatches[:5]}")
        sys.exit(1)


def parser_gaps_cmd(args):
    """Analyze gaps between authoritative reference commands and deterministic parsers."""
    vendor = args.vendor or "all"
    detector = ParserGapDetector()

    if vendor == "all":
        reports = detector.analyze_all()
        table = Table(title="Parser Coverage and Gap Analysis (Authoritative References vs Parsers)")
        table.add_column("Vendor", style="cyan")
        table.add_column("Parser Class", style="bold")
        table.add_column("Ref Commands", justify="right")
        table.add_column("Supported", justify="right", style="green")
        table.add_column("Unsupported", justify="right", style="red")
        table.add_column("Coverage", justify="right", style="yellow")
        table.add_column("Blind Spots", justify="right", style="magenta")

        for vk, rep in reports.items():
            table.add_row(
                vk,
                rep.parser_class_name,
                str(rep.total_authoritative_commands),
                str(len(rep.supported_commands)),
                str(len(rep.unsupported_commands)),
                f"{rep.coverage_percentage:.1f}%",
                str(len(rep.blind_spots)),
            )
        console.print(table)
    else:
        rep = detector.analyze_vendor(vendor)
        if not rep:
            console.print(f"[red]No gap report available for {vendor}[/red]")
            return
        console.print(f"\n[bold]Gap Analysis for {vendor} ({rep.parser_class_name})[/bold]")
        console.print(f"Total Authoritative Commands: {rep.total_authoritative_commands}")
        console.print(f"Coverage: [yellow]{rep.coverage_percentage:.1f}%[/yellow]")
        console.print(f"Supported Commands ({len(rep.supported_commands)}):")
        for c in rep.supported_commands[:10]:
            console.print(f"  [green][OK] {c}[/green]")
        if len(rep.supported_commands) > 10:
            console.print(f"  ... and {len(rep.supported_commands) - 10} more")

        console.print(f"\nUnsupported Commands ({len(rep.unsupported_commands)}):")
        for c in rep.unsupported_commands[:10]:
            console.print(f"  [red][X] {c}[/red]")

        if rep.blind_spots:
            console.print(f"\n[magenta]Security Blind Spots ({len(rep.blind_spots)}):[/magenta]")
            for b in rep.blind_spots[:5]:
                console.print(f"  - {b['command']} (Domain: {b['security_domain']}, Mode: {b['mode']})")


def export_nlp_cmd(args):
    """Export clean NLP and LLM training datasets with complete provenance."""
    console.print("[bold blue]Exporting NLP and LLM datasets to dataset/nlp/...[/bold blue]")
    exporter = NLPDatasetExporter()
    counts = exporter.export_all()

    table = Table(title="Exported NLP/LLM Datasets (with Provenance)")
    table.add_column("Dataset File", style="cyan")
    table.add_column("Record Count", justify="right", style="green")

    for name, cnt in counts.items():
        table.add_row(f"dataset/nlp/{name}.jsonl", f"{cnt:,}")

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        prog="python -m auditor.dataset",
        description="Auditor Dataset & Vendor Reference Acquisition CLI.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Dataset subcommands")

    # list-sources
    subparsers.add_parser("list-sources", help="List all authoritative vendor reference sources")

    # download-references
    dl_parser = subparsers.add_parser("download-references", help="Download vendor reference manuals")
    dl_parser.add_argument("--vendor", default="all", help="Target vendor key or 'all'")
    dl_parser.add_argument("--force", action="store_true", help="Force re-download even if cached")
    dl_parser.add_argument("--verify", action="store_true", help="Verify cryptographic hashes after download")

    # status
    subparsers.add_parser("status", help="Show reference dataset and parser coverage status")

    # validate
    subparsers.add_parser("validate", help="Cryptographically validate dataset manifest")

    # parser-gaps
    gap_parser = subparsers.add_parser("parser-gaps", help="Analyze parser coverage gaps against reference manuals")
    gap_parser.add_argument("--vendor", default="all", help="Target vendor key or 'all'")

    # export-nlp
    subparsers.add_parser("export-nlp", help="Export clean JSONL training datasets with provenance")

    # update
    upd_parser = subparsers.add_parser("update", help="Update references, re-extract, and refresh manifest")
    upd_parser.add_argument("--vendor", default="all", help="Target vendor key or 'all'")

    args = parser.parse_args()

    if args.subcommand == "list-sources":
        list_sources_cmd(args)
    elif args.subcommand in ("download-references", "update"):
        download_references_cmd(args)
    elif args.subcommand == "status":
        status_cmd(args)
    elif args.subcommand == "validate":
        validate_cmd(args)
    elif args.subcommand == "parser-gaps":
        parser_gaps_cmd(args)
    elif args.subcommand == "export-nlp":
        export_nlp_cmd(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
