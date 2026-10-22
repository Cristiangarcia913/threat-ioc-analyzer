"""
Módulo de Normalización de Indicadores de Compromiso (IOCs).
Estandariza IPs, dominios y URLs a formatos canónicos según estándares RFC.
"""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, unquote


class IOCNormalizer:
    """
    Normalizador de IOCs para homologar formatos previo a clasificación y análisis.
    """

    @staticmethod
    def extract_ip_and_port(text: str) -> Tuple[str, Optional[int]]:
        """
        Extrae la dirección IP y el puerto opcional (ej: 192.168.1.1:8080 o [::1]:8080).
        """
        text = text.strip()

        # IPv6 con puerto: [2001:db8::1]:8080
        ipv6_port_match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d{1,5}))?$', text)
        if ipv6_port_match:
            ip_str = ipv6_port_match.group(1)
            port = int(ipv6_port_match.group(2)) if ipv6_port_match.group(2) else None
            return ip_str, port

        # IPv4 con puerto: 1.2.3.4:8080
        ipv4_port_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$', text)
        if ipv4_port_match:
            ip_str = ipv4_port_match.group(1)
            port = int(ipv4_port_match.group(2)) if ipv4_port_match.group(2) else None
            return ip_str, port

        return text, None

    def normalize_ip(self, ip_str: str) -> Optional[str]:
        """
        Normaliza una dirección IPv4 o IPv6 a su representación canónica.
        """
        clean_ip, port = self.extract_ip_and_port(ip_str)
        try:
            addr = ipaddress.ip_address(clean_ip)
            canonical = str(addr)
            if port is not None and 1 <= port <= 65535:
                if isinstance(addr, ipaddress.IPv6Address):
                    return f"[{canonical}]:{port}"
                return f"{canonical}:{port}"
            return canonical
        except ValueError:
            return None

    def normalize_domain(self, domain_str: str) -> Optional[str]:
        """
        Normaliza un nombre de dominio (minúsculas, sin esquemas ni rutas).
        """
        if not domain_str or not isinstance(domain_str, str):
            return None

        clean = domain_str.strip().lower()

        # Si viene con esquema http/https, extraer solo el host
        if clean.startswith(('http://', 'https://', 'ftp://')):
            parsed = urlparse(clean)
            clean = parsed.netloc or parsed.path

        # Eliminar posible puerto
        clean = clean.split(':')[0]
        # Eliminar barra final
        clean = clean.rstrip('/')

        # Validar estructura básica de dominio (etiquetas separadas por punto con TLD >= 2 chars)
        domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if re.match(domain_pattern, clean):
            return clean

        return None

    def normalize_url(self, url_str: str) -> Optional[str]:
        """
        Normaliza una URL: decodifica caracteres seguros, homogeneiza esquema y host
        a minúsculas y preserva la ruta/query.
        """
        if not url_str or not isinstance(url_str, str):
            return None

        url_clean = url_str.strip()

        # Si no tiene esquema pero parece URL con ruta
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_clean):
            url_clean = 'http://' + url_clean

        try:
            parsed = urlparse(url_clean)
            if not parsed.netloc:
                return None

            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = unquote(parsed.path) or '/'
            query = f"?{unquote(parsed.query)}" if parsed.query else ""
            fragment = f"#{unquote(parsed.fragment)}" if parsed.fragment else ""

            return f"{scheme}://{netloc}{path}{query}{fragment}"
        except Exception:
            return None

    def normalize_ioc(self, ioc: str) -> Optional[str]:
        """
        Identifica automáticamente el formato y normaliza el IOC.
        """
        if not ioc or not isinstance(ioc, str):
            return None

        clean = ioc.strip()

        # 1. Comprobar si es IP (con o sin puerto)
        ip_norm = self.normalize_ip(clean)
        if ip_norm:
            return ip_norm

        # 2. Comprobar si es URL explícita (con esquema o barras de ruta)
        if re.match(r'^(https?|ftp)://', clean, re.IGNORECASE) or '/' in clean:
            url_norm = self.normalize_url(clean)
            if url_norm:
                return url_norm

        # 3. Comprobar si es Dominio
        domain_norm = self.normalize_domain(clean)
        if domain_norm:
            return domain_norm

        return clean


# Instancia por defecto
default_normalizer = IOCNormalizer()


def normalize(ioc: str) -> Optional[str]:
    """Acceso rápido funcional al normalizador."""
    return default_normalizer.normalize_ioc(ioc)
