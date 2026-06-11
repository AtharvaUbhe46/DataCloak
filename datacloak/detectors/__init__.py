"""
DataCloak detector modules.

All built-in detectors are exported from this package.
"""

from .aadhaar import AadhaarDetector
from .base import BaseDetector, Detection
from .credit_card import CreditCardDetector
from .email import EmailDetector
from .ifsc import IFSCDetector
from .ip_address import IPAddressDetector
from .mobile import MobileDetector
from .pan import PANDetector
from .upi import UPIDetector

__all__ = [
    "BaseDetector",
    "Detection",
    "AadhaarDetector",
    "PANDetector",
    "MobileDetector",
    "EmailDetector",
    "UPIDetector",
    "CreditCardDetector",
    "IFSCDetector",
    "IPAddressDetector",
]

#: Registry of all built-in detectors (ordered by detection priority)
DEFAULT_DETECTORS: list[BaseDetector] = [
    AadhaarDetector(),
    PANDetector(),
    MobileDetector(),
    EmailDetector(),
    UPIDetector(),
    CreditCardDetector(),
    IFSCDetector(),
    IPAddressDetector(),
]
