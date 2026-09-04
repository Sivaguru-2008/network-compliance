"""Document extraction pipeline for PDF, HTML, and Markdown vendor references."""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pypdf
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class DocumentSection:
    heading: str
    level: int
    content: str
    page_number: Optional[int] = None
    code_blocks: List[str] = field(default_factory=list)


@dataclass
class ExtractedDocument:
    vendor_key: str
    document_title: str
    source_filename: str
    source_format: str
    total_pages: int
    total_sections: int
    total_code_blocks: int
    sections: List[DocumentSection]
    extracted_text_path: str
    extracted_json_path: str
    version: str = ""


class DocumentExtractor:
    """Extracts structured text, sections, and command blocks from vendor manuals."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.vendor_ref_base = self.dataset_base / "vendor_references"

    def extract_pdf(self, pdf_path: Path, vendor_key: str, doc_title: str = "", version: str = "") -> ExtractedDocument:
        """Extract structured sections, pages, and code snippets from a PDF file."""
        reader = pypdf.PdfReader(str(pdf_path))
        total_pages = len(reader.pages)
        sections: List[DocumentSection] = []
        full_text_lines: List[str] = []
        total_code_blocks = 0

        current_heading = "Document Start"
        current_section_lines: List[str] = []
        current_code_blocks: List[str] = []
        current_page = 1

        for idx, page in enumerate(reader.pages):
            page_num = idx + 1
            try:
                page_text = page.extract_text() or ""
            except Exception as e:
                logger.warning("Error extracting text from page %d of %s: %s", page_num, pdf_path, e)
                page_text = ""

            full_text_lines.append(f"--- [Page {page_num}] ---")
            full_text_lines.append(page_text)

            # Analyze lines for headings and command syntax
            for line in page_text.splitlines():
                clean = line.strip()
                if not clean:
                    continue

                # Heading detection heuristic (short uppercase or numbered chapter/section)
                if (len(clean) < 80 and (clean.isupper() or re.match(r"^(Chapter\s+\d+|Section\s+\d+|\d+\.\d+|\b[A-Z][a-zA-Z0-9\s-]{3,50}:?$)", clean))):
                    if current_section_lines:
                        sections.append(DocumentSection(
                            heading=current_heading,
                            level=1,
                            content="\n".join(current_section_lines),
                            page_number=current_page,
                            code_blocks=list(current_code_blocks),
                        ))
                        current_section_lines = []
                        current_code_blocks = []
                    current_heading = clean
                    current_page = page_num
                else:
                    current_section_lines.append(clean)
                    # Detect potential command or config lines
                    if re.match(r"^(#|\$|>|switch|router|fg|FW|panos|config|set|edit|rule|ip|interface|system|service|logging|snmp|banner)\b", clean, re.IGNORECASE):
                        current_code_blocks.append(clean)
                        total_code_blocks += 1

        if current_section_lines:
            sections.append(DocumentSection(
                heading=current_heading,
                level=1,
                content="\n".join(current_section_lines),
                page_number=current_page,
                code_blocks=list(current_code_blocks),
            ))

        extracted_dir = self.vendor_ref_base / vendor_key / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        stem = pdf_path.stem

        txt_path = extracted_dir / f"{stem}.extracted.txt"
        json_path = extracted_dir / f"{stem}.extracted.json"

        txt_path.write_text("\n".join(full_text_lines), encoding="utf-8")

        extracted_doc = ExtractedDocument(
            vendor_key=vendor_key,
            document_title=doc_title or stem,
            source_filename=pdf_path.name,
            source_format="pdf",
            total_pages=total_pages,
            total_sections=len(sections),
            total_code_blocks=total_code_blocks,
            sections=sections,
            extracted_text_path=str(txt_path.relative_to(self.dataset_base)),
            extracted_json_path=str(json_path.relative_to(self.dataset_base)),
            version=version,
        )

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "vendor_key": extracted_doc.vendor_key,
                "document_title": extracted_doc.document_title,
                "source_filename": extracted_doc.source_filename,
                "source_format": extracted_doc.source_format,
                "total_pages": extracted_doc.total_pages,
                "total_sections": extracted_doc.total_sections,
                "total_code_blocks": extracted_doc.total_code_blocks,
                "version": extracted_doc.version,
                "sections": [asdict(s) for s in extracted_doc.sections],
            }, f, indent=2)

        return extracted_doc

    def extract_html(self, html_path: Path, vendor_key: str, doc_title: str = "", version: str = "") -> ExtractedDocument:
        """Extract structured headings, paragraphs, and code blocks from an HTML manual."""
        html_content = html_path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(html_content, "html.parser")

        # Strip scripts and styles
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        sections: List[DocumentSection] = []
        full_text_lines: List[str] = []
        total_code_blocks = 0

        # Extract code blocks
        all_code_blocks: List[str] = []
        for pre in soup.find_all(["pre", "code"]):
            block_text = pre.get_text().strip()
            if block_text and len(block_text) > 3:
                all_code_blocks.append(block_text)
                total_code_blocks += 1

        # Extract sections by headings
        current_heading = doc_title or soup.title.string.strip() if soup.title else html_path.stem
        current_lines: List[str] = []
        current_codes: List[str] = []

        for elem in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "li", "table"]):
            tag_name = elem.name.lower()
            text = elem.get_text().strip()
            if not text:
                continue

            if tag_name in ("h1", "h2", "h3", "h4"):
                if current_lines:
                    sections.append(DocumentSection(
                        heading=current_heading,
                        level=int(tag_name[1]) if tag_name[1].isdigit() else 1,
                        content="\n".join(current_lines),
                        page_number=1,
                        code_blocks=list(current_codes),
                    ))
                    current_lines = []
                    current_codes = []
                current_heading = text
                full_text_lines.append(f"\n## {text}\n")
            elif tag_name in ("pre", "code"):
                current_codes.append(text)
                current_lines.append(f"```\n{text}\n```")
                full_text_lines.append(f"```\n{text}\n```")
            else:
                current_lines.append(text)
                full_text_lines.append(text)

        if current_lines:
            sections.append(DocumentSection(
                heading=current_heading,
                level=1,
                content="\n".join(current_lines),
                page_number=1,
                code_blocks=list(current_codes),
            ))

        extracted_dir = self.vendor_ref_base / vendor_key / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        stem = html_path.stem

        txt_path = extracted_dir / f"{stem}.extracted.txt"
        json_path = extracted_dir / f"{stem}.extracted.json"

        txt_path.write_text("\n".join(full_text_lines), encoding="utf-8")

        extracted_doc = ExtractedDocument(
            vendor_key=vendor_key,
            document_title=doc_title or current_heading,
            source_filename=html_path.name,
            source_format="html",
            total_pages=1,
            total_sections=len(sections),
            total_code_blocks=total_code_blocks,
            sections=sections,
            extracted_text_path=str(txt_path.relative_to(self.dataset_base)),
            extracted_json_path=str(json_path.relative_to(self.dataset_base)),
            version=version,
        )

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "vendor_key": extracted_doc.vendor_key,
                "document_title": extracted_doc.document_title,
                "source_filename": extracted_doc.source_filename,
                "source_format": extracted_doc.source_format,
                "total_pages": extracted_doc.total_pages,
                "total_sections": extracted_doc.total_sections,
                "total_code_blocks": extracted_doc.total_code_blocks,
                "version": extracted_doc.version,
                "sections": [asdict(s) for s in extracted_doc.sections],
            }, f, indent=2)

        return extracted_doc

    def extract_markdown(self, md_path: Path, vendor_key: str, doc_title: str = "", version: str = "") -> ExtractedDocument:
        """Extract structured sections, code fences, and command lists from a Markdown file."""
        md_text = md_path.read_text(encoding="utf-8", errors="ignore")
        lines = md_text.splitlines()

        sections: List[DocumentSection] = []
        current_heading = doc_title or md_path.stem
        current_lines: List[str] = []
        current_codes: List[str] = []
        in_code_block = False
        temp_code_lines: List[str] = []
        total_code_blocks = 0

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                if in_code_block:
                    in_code_block = False
                    code_str = "\n".join(temp_code_lines)
                    current_codes.append(code_str)
                    total_code_blocks += 1
                    temp_code_lines = []
                else:
                    in_code_block = True
                    temp_code_lines = []
                continue

            if in_code_block:
                temp_code_lines.append(line)
                continue

            if stripped.startswith("#"):
                match = re.match(r"^(#+)\s*(.*)$", stripped)
                if match:
                    level = len(match.group(1))
                    h_text = match.group(2)
                    if current_lines:
                        sections.append(DocumentSection(
                            heading=current_heading,
                            level=1,
                            content="\n".join(current_lines),
                            page_number=1,
                            code_blocks=list(current_codes),
                        ))
                        current_lines = []
                        current_codes = []
                    current_heading = h_text
                    continue

            current_lines.append(line)

        if current_lines:
            sections.append(DocumentSection(
                heading=current_heading,
                level=1,
                content="\n".join(current_lines),
                page_number=1,
                code_blocks=list(current_codes),
            ))

        extracted_dir = self.vendor_ref_base / vendor_key / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        stem = md_path.stem

        txt_path = extracted_dir / f"{stem}.extracted.txt"
        json_path = extracted_dir / f"{stem}.extracted.json"

        txt_path.write_text(md_text, encoding="utf-8")

        extracted_doc = ExtractedDocument(
            vendor_key=vendor_key,
            document_title=doc_title or stem,
            source_filename=md_path.name,
            source_format="markdown",
            total_pages=1,
            total_sections=len(sections),
            total_code_blocks=total_code_blocks,
            sections=sections,
            extracted_text_path=str(txt_path.relative_to(self.dataset_base)),
            extracted_json_path=str(json_path.relative_to(self.dataset_base)),
            version=version,
        )

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "vendor_key": extracted_doc.vendor_key,
                "document_title": extracted_doc.document_title,
                "source_filename": extracted_doc.source_filename,
                "source_format": extracted_doc.source_format,
                "total_pages": extracted_doc.total_pages,
                "total_sections": extracted_doc.total_sections,
                "total_code_blocks": extracted_doc.total_code_blocks,
                "version": extracted_doc.version,
                "sections": [asdict(s) for s in extracted_doc.sections],
            }, f, indent=2)

        return extracted_doc

    def extract_document(self, file_path: Path, vendor_key: str, doc_title: str = "", version: str = "") -> ExtractedDocument:
        """Dispatcher for extracting text from any supported document format."""
        suffix = file_path.suffix.lower()
        if suffix == ".pdf":
            return self.extract_pdf(file_path, vendor_key, doc_title, version)
        elif suffix in (".html", ".htm"):
            return self.extract_html(file_path, vendor_key, doc_title, version)
        elif suffix in (".md", ".markdown"):
            return self.extract_markdown(file_path, vendor_key, doc_title, version)
        else:
            raise ValueError(f"Unsupported document format: {suffix}")
