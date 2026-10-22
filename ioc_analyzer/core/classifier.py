"""
Módulo de Clasificación de Indicadores de Compromiso (IOCs).
Clasifica de forma precisa entre IPv4, IPv6, Dominio, URL, Email y Hashes criptográficos.
"""

import ipaddress
import re
from typing import Dict, Any


class IOCType:
    IPV4 = "IPv4"
    IPV4_PORT = "IPv4:Port"
    IPV6 = "IPv6"
    IPV6_PORT = "IPv6:Port"
    DOMAIN = "Dominio"
    URL = "URL"
    EMAIL = "Email"
    HASH_MD5 = "Hash (MD5)"
    HASH_SHA1 = "Hash (SHA-1)"
    HASH_SHA256 = "Hash (SHA-256)"
    UNKNOWN = "Desconocido"


class IOCClassifier:
    """
    Motor de clasificación con heurística en cascada basada en especificidad.
    """

    PATTERNS = {
        'url': r'^(https?|ftp)://[^\s/$.?#].[^\s]*$',
        'domain': r'^(?!(\d{1,3}\.){3}\d{1,3}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
        'email': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
    }

    def classify(self, ioc: str) -> str:
        """
        Determina la categoría del IOC analizado.
        """
        if not ioc or not isinstance(ioc, str):
            return IOCType.UNKNOWN

        clean = ioc.strip()

        # 1. Hashes criptográficos
        if re.match(self.PATTERNS['md5'], clean):
            return IOCType.HASH_MD5
        if re.match(self.PATTERNS['sha1'], clean):
            return IOCType.HASH_SHA1
        if re.match(self.PATTERNS['sha256'], clean):
            return IOCType.HASH_SHA256

        # 2. Correo electrónico
        if re.match(self.PATTERNS['email'], clean):
            return IOCType.EMAIL

        # 3. URL completa con protocolo o barras de ruta
        if re.match(self.PATTERNS['url'], clean, re.IGNORECASE) or (re.match(r'^(https?|ftp)://', clean, re.IGNORECASE)):
            return IOCType.URL

        # 4. Dirección IP pura o con puerto
        # Caso IPv4 con puerto
        ipv4_port = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$', clean)
        if ipv4_port:
            try:
                ipaddress.IPv4Address(ipv4_port.group(1))
                port = int(ipv4_port.group(2))
                if 1 <= port <= 65535:
                    return IOCType.IPV4_PORT
            except ValueError:
                pass

        # Caso IPv6 con puerto: [::1]:8080
        ipv6_port = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d{1,5})$', clean)
        if ipv6_port:
            try:
                ipaddress.IPv6Address(ipv6_port.group(1))
                port = int(ipv6_port.group(2))
                if 1 <= port <= 65535:
                    return IOCType.IPV6_PORT
            except ValueError:
                pass

        # Caso IP pura (IPv4 o IPv6)
        try:
            addr = ipaddress.ip_address(clean)
            if isinstance(addr, ipaddress.IPv4Address):
                return IOCType.IPV4
            elif isinstance(addr, ipaddress.IPv6Address):
                return IOCType.IPV6
        except ValueError:
            pass

        # 5. Nombre de Dominio
        if re.match(self.PATTERNS['domain'], clean):
            return IOCType.DOMAIN

        return IOCType.UNKNOWN

    def classify_detailed(self, ioc: str) -> Dict[str, Any]:
        """
        Retorna información detallada de la clasificación.
        """
        tipo = self.classify(ioc)
        return {
            "ioc": ioc,
            "tipo": tipo,
            "es_ip": tipo in (IOCType.IPV4, IOCType.IPV4_PORT, IOCType.IPV6, IOCType.IPV6_PORT),
            "es_red": tipo in (IOCType.IPV4, IOCType.IPV4_PORT, IOCType.IPV6, IOCType.IPV6_PORT, IOCType.DOMAIN, IOCType.URL),
            "es_hash": tipo in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)
        }


# Instancia por defecto
default_classifier = IOCClassifier()


def classify(ioc: str) -> str:
    """Acceso rápido funcional al clasificador."""
    return default_classifier.classify(ioc)
