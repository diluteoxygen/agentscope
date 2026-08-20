"""
AgentScope: AI Coding Agent Authority Forensics & Capability Fingerprinting
"""

__version__ = "0.1.0"

from .models import CapabilityFingerprint, FilesystemCapabilities, CapabilityDelta, RiskLevel
from .normalizer import Normalizer
from .observer import TraceObserver
from .diff import diff_fingerprints

__all__ = [
    "CapabilityFingerprint",
    "FilesystemCapabilities",
    "CapabilityDelta",
    "RiskLevel",
    "Normalizer",
    "TraceObserver",
    "diff_fingerprints",
]
