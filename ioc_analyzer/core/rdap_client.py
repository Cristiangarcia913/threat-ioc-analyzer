"""
Módulo de Consulta RDAP (Registration Data Access Protocol) para Enriquecimiento Forense.
Reemplaza al protocolo WHOIS tradicional con respuestas JSON estructuradas según RFC 7480-7484.
"""

import ipaddress
import re
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlparse
import requests


class RDAPClient:
    """
    Cliente RDAP con bootstrap dinámico para resolver cualquier dominio o IP global.
    """

    BOOTSTRAP_URL = "https://rdap.org"

    def __init__(self, timeout: float = 10.0, user_agent: str = "Threat-IOC-Analyzer/1.0"):
        self.timeout = timeout
        self.headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": user_agent
        }

    def extract_rdap_target(self, ioc: str) -> Tuple[Optional[str], str]:
        """
        Extrae el identificador limpio para la consulta y determina si es 'ip' o 'domain'.
        """
        if not ioc or not isinstance(ioc, str):
            return None, "unknown"

        clean = ioc.strip()

        # Si es URL
        if re.match(r'^(https?|ftp)://', clean, re.IGNORECASE):
            try:
                parsed = urlparse(clean)
                host = parsed.hostname
                if host:
                    clean = host
            except Exception:
                pass

        # Quitar rutas residuales
        if '/' in clean:
            clean = clean.split('/')[0]

        # Quitar puerto si existe
        if ':' in clean and not clean.startswith('['):
            parts = clean.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                clean = parts[0]

        # Comprobar si es IP
        try:
            ipaddress.ip_address(clean)
            return clean, "ip"
        except ValueError:
            pass

        # Si es dominio
        clean_domain = clean.lower().rstrip('.')
        if '.' in clean_domain:
            return clean_domain, "domain"

        return None, "unknown"

    def _extract_dates(self, rdap_data: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """
        Extrae fechas clave (registro, expiración, última modificación) del bloque 'events'.
        """
        dates: Dict[str, Optional[str]] = {
            "registration": None,
            "expiration": None,
            "last_changed": None
        }

        events = rdap_data.get("events", [])
        if isinstance(events, list):
            for event in events:
                action = event.get("eventAction", "").lower()
                date_str = event.get("eventDate")
                if action == "registration":
                    dates["registration"] = date_str
                elif action == "expiration":
                    dates["expiration"] = date_str
                elif action in ("last changed", "last updated"):
                    dates["last_changed"] = date_str

        return dates

    def _extract_entities_and_abuse(self, rdap_data: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
        """
        Extrae nombres de organizaciones y correos de contacto para abuso (abuse contact).
        """
        org_names: List[str] = []
        abuse_email: Optional[str] = None

        entities = rdap_data.get("entities", [])
        if isinstance(entities, list):
            for entity in entities:
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [])

                # Extraer nombre si existe en vCard
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) > 3:
                            prop_name = item[0]
                            prop_val = item[3]
                            if prop_name == "fn" and prop_val and prop_val not in org_names:
                                org_names.append(str(prop_val))
                            if prop_name == "email" and ("abuse" in roles or not abuse_email):
                                abuse_email = str(prop_val)

                # Comprobar sub-entidades (muy común en ARIN y RIPE)
                sub_entities = entity.get("entities", [])
                for sub in sub_entities:
                    sub_roles = sub.get("roles", [])
                    sub_vcard = sub.get("vcardArray", [])
                    if len(sub_vcard) > 1 and isinstance(sub_vcard[1], list):
                        for item in sub_vcard[1]:
                            if len(item) > 3 and item[0] == "email" and "abuse" in sub_roles:
                                abuse_email = str(item[3])

        return org_names, abuse_email

    def query(self, ioc: str) -> Dict[str, Any]:
        """
        Consulta información RDAP para un IOC (IP o Dominio).
        """
        target, target_type = self.extract_rdap_target(ioc)

        result: Dict[str, Any] = {
            "ioc": ioc,
            "target": target,
            "query_type": target_type,
            "status": "error",
            "handle": None,
            "name": None,
            "country": None,
            "ip_range": None,
            "registration_date": None,
            "expiration_date": None,
            "last_changed_date": None,
            "abuse_email": None,
            "entities": [],
            "statuses": [],
            "nameservers": [],
            "error_message": None,
            "raw_data": None
        }

        if not target or target_type == "unknown":
            result["error_message"] = "IOC incompatible con consultas RDAP (debe ser IP o Dominio)"
            return result

        url = f"{self.BOOTSTRAP_URL}/{target_type}/{target}"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )

            if response.status_code == 404:
                result["status"] = "not_found"
                result["error_message"] = f"Recurso no encontrado en RDAP (HTTP 404)"
                return result

            response.raise_for_status()
            data = response.json()
            result["raw_data"] = data
            result["status"] = "success"

            # Parsear datos estándar
            result["handle"] = data.get("handle")
            result["name"] = data.get("name") or data.get("ldhName")
            result["country"] = data.get("country")
            result["statuses"] = data.get("status", [])

            # Si es IP, rango de direcciones
            if target_type == "ip":
                start_ip = data.get("startAddress")
                end_ip = data.get("endAddress")
                if start_ip and end_ip:
                    result["ip_range"] = f"{start_ip} - {end_ip}"

            # Si es dominio, nameservers
            if target_type == "domain":
                ns_list = data.get("nameservers", [])
                result["nameservers"] = [ns.get("ldhName") for ns in ns_list if ns.get("ldhName")]

            # Fechas
            dates = self._extract_dates(data)
            result["registration_date"] = dates["registration"]
            result["expiration_date"] = dates["expiration"]
            result["last_changed_date"] = dates["last_changed"]

            # Entidades y contacto de abuso
            entities, abuse = self._extract_entities_and_abuse(data)
            result["entities"] = entities
            result["abuse_email"] = abuse

        except requests.exceptions.Timeout:
            result["status"] = "timeout"
            result["error_message"] = f"Tiempo de espera agotado ({self.timeout}s) al consultar RDAP"
        except requests.exceptions.RequestException as e:
            result["status"] = "error"
            result["error_message"] = f"Error en la conexión RDAP: {str(e)}"
        except Exception as e:
            result["status"] = "error"
            result["error_message"] = f"Error al procesar respuesta RDAP: {str(e)}"

        return result


# Instancia por defecto
default_rdap_client = RDAPClient()


def query_rdap(ioc: str) -> Dict[str, Any]:
    """Acceso rápido funcional al cliente RDAP."""
    return default_rdap_client.query(ioc)
