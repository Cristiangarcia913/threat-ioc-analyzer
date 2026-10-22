"""
Núcleo del motor de análisis forense de IOCs.
"""

from .deobfuscator import deobfuscate, defang, is_obfuscated
from .normalizer import IOCNormalizer, normalize
from .classifier import IOCClassifier, IOCType, classify
from .dns_resolver import DNSResolver, resolve_dns
from .rdap_client import RDAPClient, query_rdap
from .exporter import IOCExporter
from .pipeline import IOCPipeline, analyze

__all__ = [
    "deobfuscate",
    "defang",
    "is_obfuscated",
    "IOCNormalizer",
    "normalize",
    "IOCClassifier",
    "IOCType",
    "classify",
    "DNSResolver",
    "resolve_dns",
    "RDAPClient",
    "query_rdap",
    "IOCExporter",
    "IOCPipeline",
    "analyze"
]
