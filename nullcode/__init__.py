"""Nullcode package initialization"""

__version__ = "1.0.0"
__author__ = "Null Security Team"
__description__ = "AI-powered vulnerability scanner for ethical hackers"

from .core import Scanner, ScanResult, VulnerabilityMatch
from .ui import Animations

__all__ = ["Scanner", "ScanResult", "VulnerabilityMatch", "Animations", "__version__"]
