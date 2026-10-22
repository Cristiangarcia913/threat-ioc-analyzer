"""
Módulo de Pipeline Unificado para Procesamiento y Enriquecimiento de IOCs.
Ejecuta el ciclo de vida forense completo: Desofuscar -> Normalizar -> Clasificar -> DNS -> RDAP.
"""

from typing import List, Dict, Any, Optional, Callable
from .deobfuscator import deobfuscate, is_obfuscated
from .normalizer import normalize
from .classifier import classify
from .dns_resolver import DNSResolver, default_dns_resolver
from .rdap_client import RDAPClient, default_rdap_client


class IOCPipeline:
    """
    Orquestador del pipeline forense de análisis de IOCs.
    """

    def __init__(
        self,
        dns_resolver: Optional[DNSResolver] = None,
        rdap_client: Optional[RDAPClient] = None
    ):
        self.dns = dns_resolver or default_dns_resolver
        self.rdap = rdap_client or default_rdap_client

    def process_single(
        self,
        raw_ioc: str,
        skip_dns: bool = False,
        skip_rdap: bool = False
    ) -> Dict[str, Any]:
        """
        Ejecuta el flujo completo para un único IOC.
        """
        raw_clean = raw_ioc.strip()

        # 1. Comprobación de ofuscación y Desofuscación
        was_obfuscated = is_obfuscated(raw_clean)
        deobfuscated = deobfuscate(raw_clean)

        # 2. Normalización
        normalized = normalize(deobfuscated) or deobfuscated

        # 3. Clasificación
        ioc_type = classify(normalized)

        # Estructura base del resultado
        result: Dict[str, Any] = {
            "original": raw_clean,
            "was_obfuscated": was_obfuscated,
            "deobfuscated": deobfuscated,
            "normalized": normalized,
            "type": ioc_type,
            "dns": {},
            "rdap": {}
        }

        # 4. Resolución DNS (solo si es de tipo red: IP, dominio o URL)
        if not skip_dns and ioc_type in ("IPv4", "IPv4:Port", "IPv6", "IPv6:Port", "Dominio", "URL"):
            result["dns"] = self.dns.resolve(normalized)

        # 5. Consulta RDAP (solo para IPs, dominios o URLs)
        if not skip_rdap and ioc_type in ("IPv4", "IPv4:Port", "IPv6", "IPv6:Port", "Dominio", "URL"):
            result["rdap"] = self.rdap.query(normalized)

        return result

    def process_batch(
        self,
        iocs: List[str],
        skip_dns: bool = False,
        skip_rdap: bool = False,
        on_progress: Optional[Callable[[int, int, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Procesa una lista de IOCs con reporte de progreso opcional.
        """
        results = []
        total = len(iocs)

        for idx, ioc in enumerate(iocs, 1):
            ioc_clean = ioc.strip()
            if not ioc_clean or ioc_clean.startswith("#"):
                continue

            if on_progress:
                on_progress(idx, total, ioc_clean)

            res = self.process_single(ioc_clean, skip_dns=skip_dns, skip_rdap=skip_rdap)
            results.append(res)

        return results

    def process_file(
        self,
        filepath: str,
        skip_dns: bool = False,
        skip_rdap: bool = False,
        on_progress: Optional[Callable[[int, int, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Lee un archivo de texto con IOCs (uno por línea) y los analiza.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return self.process_batch(lines, skip_dns=skip_dns, skip_rdap=skip_rdap, on_progress=on_progress)


# Instancia por defecto
default_pipeline = IOCPipeline()


def analyze(raw_ioc: str, skip_dns: bool = False, skip_rdap: bool = False) -> Dict[str, Any]:
    """Acceso rápido funcional al pipeline para un IOC."""
    return default_pipeline.process_single(raw_ioc, skip_dns=skip_dns, skip_rdap=skip_rdap)
