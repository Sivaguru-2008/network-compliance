"""AI-driven multi-vendor network security compliance auditor -- deterministic core.

Pipeline (each arrow is a stable contract):

    config text -> VendorParser -> SecurityBaselineModel -> ComplianceEngine
                -> AuditReport -> {CLI table, JSON}
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
