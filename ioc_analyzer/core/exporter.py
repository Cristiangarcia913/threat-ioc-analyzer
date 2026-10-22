"""
Módulo de Exportación y Generación de Reportes Forenses.
Soporta formatos JSON, CSV, Texto plano y Markdown para informes periciales.
"""

import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional


class IOCExporter:
    """
    Generador de informes forenses multidispositivo.
    """

    @staticmethod
    def to_json(results: List[Dict[str, Any]], filepath: Optional[str] = None) -> str:
        """
        Serializa los resultados a JSON con metadatos de auditoría.
        """
        payload = {
            "metadata": {
                "tool": "Threat-IOC-Analyzer",
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_iocs": len(results)
            },
            "results": results
        }
        json_str = json.dumps(payload, indent=2, ensure_ascii=False)
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    @staticmethod
    def to_csv(results: List[Dict[str, Any]], filepath: Optional[str] = None) -> str:
        """
        Exporta resultados tabulares en formato CSV para ingestión en SIEM/Excel.
        """
        headers = [
            "ioc_original",
            "ioc_desofuscado",
            "ioc_normalizado",
            "tipo",
            "dns_target",
            "dns_ipv4",
            "dns_ipv6",
            "dns_ptr",
            "rdap_handle",
            "rdap_name",
            "rdap_range",
            "rdap_registration",
            "rdap_expiration",
            "rdap_abuse_email"
        ]

        rows = []
        for r in results:
            dns = r.get("dns", {})
            rdap = r.get("rdap", {})
            rows.append({
                "ioc_original": r.get("original", ""),
                "ioc_desofuscado": r.get("deobfuscated", ""),
                "ioc_normalizado": r.get("normalized", ""),
                "tipo": r.get("type", ""),
                "dns_target": dns.get("target", ""),
                "dns_ipv4": ", ".join(dns.get("A", [])),
                "dns_ipv6": ", ".join(dns.get("AAAA", [])),
                "dns_ptr": dns.get("PTR", "") or "",
                "rdap_handle": rdap.get("handle", "") or "",
                "rdap_name": rdap.get("name", "") or "",
                "rdap_range": rdap.get("ip_range", "") or "",
                "rdap_registration": rdap.get("registration_date", "") or "",
                "rdap_expiration": rdap.get("expiration_date", "") or "",
                "rdap_abuse_email": rdap.get("abuse_email", "") or ""
            })

        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
        csv_str = output.getvalue()

        if filepath:
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.write(csv_str)
        return csv_str

    @staticmethod
    def to_markdown_table(results: List[Dict[str, Any]], filepath: Optional[str] = None) -> str:
        """
        Genera una tabla Markdown para resúmenes ejecutivos e informes.
        """
        lines = [
            "# Resumen de Análisis Forense de IOCs",
            f"**Fecha de Análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Total de Indicadores:** {len(results)}\n",
            "| Original | Normalizado | Tipo | Registros DNS (A/PTR) | Entidad / RDAP | Expiración |",
            "|---|---|---|---|---|---|"
        ]

        for r in results:
            dns = r.get("dns", {})
            rdap = r.get("rdap", {})

            dns_info = []
            if dns.get("A"):
                dns_info.append("A: " + ", ".join(dns["A"][:2]))
            if dns.get("PTR") and dns.get("PTR") != "No se encontró registro PTR":
                dns_info.append(f"PTR: {dns['PTR']}")
            dns_str = "<br>".join(dns_info) if dns_info else "N/A"

            entidad = rdap.get("name") or rdap.get("handle") or "N/A"
            expiracion = rdap.get("expiration_date") or "N/A"
            if len(expiracion) > 10:
                expiracion = expiracion[:10]

            orig = r.get("original", "")
            norm = r.get("normalized", "")
            tipo = r.get("type", "")

            lines.append(f"| `{orig}` | `{norm}` | **{tipo}** | {dns_str} | {entidad} | {expiracion} |")

        md_str = "\n".join(lines) + "\n"
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md_str)
        return md_str

    @staticmethod
    def to_text_report(results: List[Dict[str, Any]], filepath: Optional[str] = None) -> str:
        """
        Genera un informe textual detallado compatible con los reportes de DFIR.
        """
        lines = [
            "=" * 70,
            "               INFORME DE ANÁLISIS FORENSE DE IOCs",
            "=" * 70,
            f"Fecha de generación : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Indicadores totales : {len(results)}",
            "=" * 70,
            ""
        ]

        for i, r in enumerate(results, 1):
            lines.append(f"[{i}/{len(results)}] INDICADOR: {r.get('original')}")
            lines.append("-" * 50)
            lines.append(f"  • Desofuscado   : {r.get('deobfuscated')}")
            lines.append(f"  • Normalizado   : {r.get('normalized')}")
            lines.append(f"  • Clasificación : {r.get('type')}")

            # DNS
            dns = r.get("dns", {})
            lines.append("  • Resolución DNS:")
            if dns.get("query_type") == "ip":
                lines.append(f"    - PTR         : {dns.get('PTR')}")
            else:
                a_recs = dns.get("A", [])
                lines.append(f"    - A (IPv4)    : {', '.join(a_recs) if a_recs else 'No encontrado'}")
                aaaa_recs = dns.get("AAAA", [])
                lines.append(f"    - AAAA (IPv6) : {', '.join(aaaa_recs) if aaaa_recs else 'No encontrado'}")
            if dns.get("aliases"):
                lines.append(f"    - CNAME/Alias : {', '.join(dns.get('aliases'))}")

            # RDAP
            rdap = r.get("rdap", {})
            lines.append("  • Información RDAP:")
            if rdap.get("status") == "success":
                if rdap.get("handle"):
                    lines.append(f"    - Handle      : {rdap.get('handle')}")
                if rdap.get("name"):
                    lines.append(f"    - Nombre/Org  : {rdap.get('name')}")
                if rdap.get("ip_range"):
                    lines.append(f"    - Rango IP    : {rdap.get('ip_range')}")
                if rdap.get("registration_date"):
                    lines.append(f"    - Registro    : {rdap.get('registration_date')}")
                if rdap.get("expiration_date"):
                    lines.append(f"    - Expiración  : {rdap.get('expiration_date')}")
                if rdap.get("abuse_email"):
                    lines.append(f"    - Abuse Email : {rdap.get('abuse_email')}")
            elif rdap.get("error_message"):
                lines.append(f"    - Estado      : {rdap.get('error_message')}")
            else:
                lines.append("    - Estado      : No disponible")

            lines.append("")

        text_str = "\n".join(lines)
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text_str)
        return text_str
