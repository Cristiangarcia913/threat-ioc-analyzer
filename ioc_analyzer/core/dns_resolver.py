"""
Módulo de Resolución DNS para Enriquecimiento Forense de IOCs.
Permite resolver registros directos (A, AAAA, CNAME) e inversos (PTR) con extracción automática de host.
"""

import ipaddress
import re
import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class DNSResolver:
    """
    Cliente de resolución DNS tolerante a fallos para investigación forense.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def extract_resolvable_target(self, ioc: str) -> Optional[str]:
        """
        Extrae el host o IP resoluble a partir de una URL, dominio o IP:puerto.
        """
        if not ioc or not isinstance(ioc, str):
            return None

        clean = ioc.strip()

        # Si es URL con esquema
        if re.match(r'^(https?|ftp)://', clean, re.IGNORECASE):
            try:
                parsed = urlparse(clean)
                host = parsed.hostname
                return host
            except Exception:
                pass

        # Si es URL sin esquema pero con ruta (ej: sub.domain.com/path)
        if '/' in clean and not clean.startswith('/'):
            clean = clean.split('/')[0]

        # Si tiene puerto (ej: 1.2.3.4:8080 o domain.com:443)
        if ':' in clean and not clean.startswith('['):
            # Comprobar si no es IPv6
            parts = clean.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                clean = parts[0]

        # Si es IPv6 entre corchetes con puerto
        ipv6_match = re.match(r'^\[([0-9a-fA-F:]+)\](?::\d+)?$', clean)
        if ipv6_match:
            clean = ipv6_match.group(1)

        return clean.strip().lower()

    def resolve(self, ioc: str) -> Dict[str, Any]:
        """
        Ejecuta la resolución DNS adecuada según la naturaleza del IOC.
        """
        target = self.extract_resolvable_target(ioc)
        result: Dict[str, Any] = {
            "ioc": ioc,
            "target": target,
            "query_type": "unknown",
            "A": [],
            "AAAA": [],
            "PTR": None,
            "aliases": [],
            "status": "error",
            "error_message": None
        }

        if not target:
            result["error_message"] = "No se pudo extraer un host o IP válido para resolución"
            return result

        # Configurar timeout del socket
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)

        try:
            # 1. Comprobar si el objetivo es una dirección IP
            is_ip = False
            try:
                ip_obj = ipaddress.ip_address(target)
                is_ip = True
                result["query_type"] = "ip"

                # Resolución inversa PTR
                try:
                    hostname, aliases, _ = socket.gethostbyaddr(str(ip_obj))
                    result["PTR"] = hostname
                    result["aliases"] = aliases
                    result["status"] = "success"
                except (socket.herror, socket.gaierror):
                    result["PTR"] = "No se encontró registro PTR"
                    result["status"] = "no_records"
                except socket.timeout:
                    result["PTR"] = "Timeout en resolución PTR"
                    result["status"] = "timeout"

            except ValueError:
                # No es IP, tratar como nombre de dominio / hostname
                pass

            # 2. Si es dominio / hostname, consultar A y AAAA
            if not is_ip:
                result["query_type"] = "domain"
                has_records = False

                # Registro A (IPv4)
                try:
                    hostname, aliases, ip_list = socket.gethostbyname_ex(target)
                    result["A"] = ip_list
                    result["aliases"] = aliases
                    if ip_list:
                        has_records = True
                except (socket.gaierror, socket.herror):
                    result["A"] = []
                except socket.timeout:
                    result["error_message"] = "Timeout en consulta IPv4 (A)"

                # Registro AAAA (IPv6)
                try:
                    addr_info = socket.getaddrinfo(target, None, socket.AF_INET6)
                    ipv6_list = sorted(list(set(r[4][0] for r in addr_info)))
                    result["AAAA"] = ipv6_list
                    if ipv6_list:
                        has_records = True
                except (socket.gaierror, socket.herror):
                    result["AAAA"] = []
                except socket.timeout:
                    pass

                if has_records:
                    result["status"] = "success"
                elif not result.get("error_message"):
                    result["status"] = "no_records"
                    result["error_message"] = "No se encontraron registros A o AAAA"

        except Exception as e:
            result["status"] = "error"
            result["error_message"] = str(e)
        finally:
            socket.setdefaulttimeout(original_timeout)

        return result


# Instancia por defecto
default_dns_resolver = DNSResolver()


def resolve_dns(ioc: str) -> Dict[str, Any]:
    """Acceso rápido funcional al resolver DNS."""
    return default_dns_resolver.resolve(ioc)
