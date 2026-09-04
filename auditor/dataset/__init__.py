"""Vendor reference and configuration-data acquisition pipeline package."""

from .sources import VENDOR_SOURCES, AccessType, VendorSource
from .downloader import ReferenceDownloader, DownloadResult
from .extractor import DocumentExtractor, ExtractedDocument
from .nlp_extractor import NLPCommandExtractor, ExtractedCommand
from .grammar import get_vendor_grammar, VendorGrammar
from .gap_detector import ParserGapDetector, GapReport
from .sanitizer import SecretSanitizer
from .manifest import DatasetManifestManager

__all__ = [
    "VENDOR_SOURCES",
    "AccessType",
    "VendorSource",
    "ReferenceDownloader",
    "DownloadResult",
    "DocumentExtractor",
    "ExtractedDocument",
    "NLPCommandExtractor",
    "ExtractedCommand",
    "get_vendor_grammar",
    "VendorGrammar",
    "ParserGapDetector",
    "GapReport",
    "SecretSanitizer",
    "DatasetManifestManager",
]
