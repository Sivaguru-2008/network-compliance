"""NLP and LLM training dataset export pipeline with complete provenance tracking."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class NLPTrainingRecord:
    instruction: str
    input: str
    output: str
    source_url: str
    source_document: str
    page_or_section: str
    vendor: str
    version: str
    verified: bool = True
    domain: str = "network_configuration_compliance"


class NLPDatasetExporter:
    """Exports structured NLP/LLM dataset records from extracted vendor references."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.vendor_ref_base = self.dataset_base / "vendor_references"
        self.nlp_dir = self.dataset_base / "nlp"

    def export_all(self) -> Dict[str, int]:
        self.nlp_dir.mkdir(parents=True, exist_ok=True)

        commands_path = self.nlp_dir / "commands.jsonl"
        documents_path = self.nlp_dir / "documents.jsonl"
        config_blocks_path = self.nlp_dir / "config_blocks.jsonl"
        parser_examples_path = self.nlp_dir / "parser_examples.jsonl"
        compliance_examples_path = self.nlp_dir / "compliance_examples.jsonl"

        counts = {
            "commands": 0,
            "documents": 0,
            "config_blocks": 0,
            "parser_examples": 0,
            "compliance_examples": 0,
        }

        with open(commands_path, "w", encoding="utf-8") as f_cmd, \
             open(documents_path, "w", encoding="utf-8") as f_doc, \
             open(config_blocks_path, "w", encoding="utf-8") as f_blk, \
             open(parser_examples_path, "w", encoding="utf-8") as f_parse, \
             open(compliance_examples_path, "w", encoding="utf-8") as f_comp:

            if self.vendor_ref_base.exists():
                for vendor_dir in self.vendor_ref_base.iterdir():
                    if not vendor_dir.is_dir():
                        continue
                    vendor_key = vendor_dir.name

                    # Process extracted commands
                    cmd_file = vendor_dir / "commands" / "commands.json"
                    if cmd_file.exists():
                        try:
                            with open(cmd_file, "r", encoding="utf-8") as f:
                                cmds = json.load(f)
                            for c in cmds:
                                # Command record
                                cmd_rec = NLPTrainingRecord(
                                    instruction=f"Extract the {c.get('vendor')} command and its negation",
                                    input=c.get("command", ""),
                                    output=json.dumps({
                                        "command": c.get("command"),
                                        "negated": c.get("negated_command"),
                                        "mode": c.get("mode"),
                                        "security_relevance": c.get("security_relevance"),
                                    }),
                                    source_url=c.get("source_url", ""),
                                    source_document=c.get("source_document", ""),
                                    page_or_section=c.get("page_or_section", ""),
                                    vendor=c.get("vendor", vendor_key),
                                    version=c.get("version", "latest"),
                                    verified=True,
                                )
                                f_cmd.write(json.dumps(asdict(cmd_rec)) + "\n")
                                counts["commands"] += 1

                                # Parser example record
                                parse_rec = NLPTrainingRecord(
                                    instruction=f"Parse configuration directive for security baseline auditing ({c.get('vendor')})",
                                    input=f"Configuration line: {c.get('command')}",
                                    output=json.dumps({
                                        "directive": c.get("command"),
                                        "security_domain": c.get("security_relevance") or "general_configuration",
                                        "mode": c.get("mode"),
                                    }),
                                    source_url=c.get("source_url", ""),
                                    source_document=c.get("source_document", ""),
                                    page_or_section=c.get("page_or_section", ""),
                                    vendor=c.get("vendor", vendor_key),
                                    version=c.get("version", "latest"),
                                    verified=True,
                                )
                                f_parse.write(json.dumps(asdict(parse_rec)) + "\n")
                                counts["parser_examples"] += 1
                        except Exception:
                            pass

                    # Process extracted documents
                    ext_dir = vendor_dir / "extracted"
                    if ext_dir.exists():
                        for json_file in ext_dir.glob("*.extracted.json"):
                            try:
                                with open(json_file, "r", encoding="utf-8") as f:
                                    doc_data = json.load(f)
                                for sec in doc_data.get("sections", []):
                                    doc_rec = NLPTrainingRecord(
                                        instruction=f"Summarize configuration syntax for {doc_data.get('document_title')}",
                                        input=sec.get("heading", ""),
                                        output=sec.get("content", "")[:500],
                                        source_url="",
                                        source_document=doc_data.get("source_filename", ""),
                                        page_or_section=sec.get("heading", ""),
                                        vendor=vendor_key,
                                        version=doc_data.get("version", "latest"),
                                        verified=True,
                                    )
                                    f_doc.write(json.dumps(asdict(doc_rec)) + "\n")
                                    counts["documents"] += 1

                                    if sec.get("code_blocks"):
                                        blk_rec = NLPTrainingRecord(
                                            instruction=f"Identify configuration structure block for {vendor_key}",
                                            input="\n".join(sec.get("code_blocks", [])[:5]),
                                            output=f"Section: {sec.get('heading')}",
                                            source_url="",
                                            source_document=doc_data.get("source_filename", ""),
                                            page_or_section=sec.get("heading", ""),
                                            vendor=vendor_key,
                                            version=doc_data.get("version", "latest"),
                                            verified=True,
                                        )
                                        f_blk.write(json.dumps(asdict(blk_rec)) + "\n")
                                        counts["config_blocks"] += 1
                            except Exception:
                                pass

        return counts
