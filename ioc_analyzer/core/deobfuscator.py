"""
Módulo de Desofuscación de Indicadores de Compromiso (IOCs).
Soporta técnicas estándar de defanging (desactivación segura) y refanging.
"""

import re
from typing import List, Tuple

# Patrones estándar de ofuscación / defanging comunes en CTI y DFIR
DEOBFUSCATION_PATTERNS: List[Tuple[str, str]] = [
    # Protocolos
    (r'hxxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://'),
    (r'h\*\*ps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://'),
    (r'htxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://'),
    (r'fxps?://', 'ftp://'),
    (r'f\*\*p://', 'ftp://'),
    (r'\[://\]', '://'),
    (r'\[:\]//', '://'),
    (r'\[:\]', ':'),
    (r'\[colon\]', ':'),
    (r'//\]', '//'),

    # Puntos
    (r'\[\.\]', '.'),
    (r'\(\.\)', '.'),
    (r'\{\.\}', '.'),
    (r'\[dot\]', '.'),
    (r'\(dot\)', '.'),
    (r'\{dot\}', '.'),
    (r'\\\.', '.'),

    # Arrobas (emails / credenciales)
    (r'\[@\]', '@'),
    (r'\(@\)', '@'),
    (r'\[at\]', '@'),
    (r'\(at\)', '@'),

    # Espacios y corchetes vacíos residuales
    (r'\[\s+\]', ''),
    (r'\[\]', ''),
]

# Patrones para detección rápida de ofuscación
OBFUSCATION_DETECTORS = [
    r'\[\.\]', r'\(\.\)', r'\{\.\}',
    r'\[dot\]', r'\(dot\)', r'\{dot\}',
    r'hxxp[s]?://', r'h\*\*p[s]?://', r'htxp[s]?://',
    r'\[://\]', r'\[:\]', r'\[@\]', r'\[at\]'
]


def is_obfuscated(ioc: str) -> bool:
    """
    Comprueba si una cadena contiene indicadores de estar ofuscada (defanged).
    """
    if not isinstance(ioc, str):
        return False
    return any(re.search(pattern, ioc, re.IGNORECASE) for pattern in OBFUSCATION_DETECTORS)


def deobfuscate(ioc: str) -> str:
    """
    Desofusca un indicador de compromiso (URL, dominio, IP o email).
    Convierte formatos 'defanged' a su forma analizable estándar.
    """
    if not isinstance(ioc, str):
        return ""

    resultado = ioc.strip()

    for pattern, replacement in DEOBFUSCATION_PATTERNS:
        if callable(replacement):
            resultado = re.sub(pattern, replacement, resultado, flags=re.IGNORECASE)
        else:
            resultado = re.sub(pattern, replacement, resultado, flags=re.IGNORECASE)

    # Limpieza final de espacios o saltos residuales
    return resultado.strip()


def defang(ioc: str) -> str:
    """
    Ofusca un IOC (defanging) para compartirlo de manera segura en informes,
    tickets o correos electrónicos sin generar enlaces navegables automáticos.
    """
    if not isinstance(ioc, str):
        return ""

    texto = ioc.strip()

    # Reemplazar protocolos
    texto = re.sub(r'^https://', 'hxxps://', texto, flags=re.IGNORECASE)
    texto = re.sub(r'^http://', 'hxxp://', texto, flags=re.IGNORECASE)
    texto = re.sub(r'^ftp://', 'fxp://', texto, flags=re.IGNORECASE)

    # Reemplazar puntos
    texto = texto.replace('.', '[.]')

    # Reemplazar arroba
    texto = texto.replace('@', '[@]')

    return texto
