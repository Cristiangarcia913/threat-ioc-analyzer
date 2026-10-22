"""
Threat IOC Analyzer
===================
Kit de herramientas forenses para el ciclo de vida de Indicadores de Compromiso (IOCs):
Desofuscación, Normalización, Clasificación, Resolución DNS y Enriquecimiento RDAP.

Autor: Cristian García (@Cristiangarcia913)
Versión: 1.0.0
"""

from .core import (
    deobfuscate,
    defang,
    is_obfuscated,
    normalize,
    classify,
    resolve_dns,
    query_rdap,
    IOCExporter,
    IOCPipeline,
    analyze
)

__version__ = "1.0.0"
__author__ = "Cristian García"

__all__ = [
    "deobfuscate",
    "defang",
    "is_obfuscated",
    "normalize",
    "classify",
    "resolve_dns",
    "query_rdap",
    "IOCExporter",
    "IOCPipeline",
    "analyze",
    "__version__"
]
