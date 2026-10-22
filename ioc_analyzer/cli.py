"""
Interfaz de Línea de Comandos (CLI) de Threat IOC Analyzer.
Ofrece tanto comandos directos para automatización / scripts como un menú interactivo.
"""

import argparse
import os
import sys
from typing import List

from .core.deobfuscator import deobfuscate, defang, is_obfuscated
from .core.normalizer import normalize
from .core.classifier import classify
from .core.dns_resolver import resolve_dns
from .core.rdap_client import query_rdap
from .core.exporter import IOCExporter
from .core.pipeline import IOCPipeline


def is_in_colab() -> bool:
    """Verifica si el entorno actual es Google Colab."""
    return "google.colab" in sys.modules


def run_interactive():
    """
    Menú interactivo por consola compatible con entornos locales y Google Colab.
    """
    pipeline = IOCPipeline()

    while True:
        print("\n" + "=" * 60)
        print("          🛡️  THREAT IOC ANALYZER - FORENSIC TOOL")
        print("=" * 60)
        print("1. Analizar IOC individual (Pipeline completo)")
        print("2. Procesar archivo .txt de IOCs (Lote)")
        print("3. Solo Desofuscar / Normalizar / Clasificar")
        print("4. Ofuscar IOC (Defang seguro para reportes)")
        print("5. Salir")
        print("=" * 60)

        opcion = input("Seleccione una opción (1-5): ").strip()

        if opcion == "1":
            ioc = input("\nIngrese el IOC a analizar: ").strip()
            if not ioc:
                print("❌ No se introdujo ningún IOC.")
                continue

            print(f"\n⏳ Analizando: {ioc} ...")
            res = pipeline.process_single(ioc)
            reporte = IOCExporter.to_text_report([res])
            print("\n" + reporte)

        elif opcion == "2":
            ruta_archivo = None
            if is_in_colab():
                print("\n📁 Entorno Colab detectado. Suba su archivo .txt...")
                from google.colab import files
                uploaded = files.upload()
                if uploaded:
                    ruta_archivo = list(uploaded.keys())[0]
            else:
                ruta_archivo = input("\nIntroduce la ruta del archivo .txt: ").strip(' "\'')

            if not ruta_archivo or not os.path.exists(ruta_archivo):
                print(f"❌ Archivo no encontrado: {ruta_archivo}")
                continue

            print("\nOpciones de exportación:")
            print("1. Mostrar por terminal")
            print("2. Guardar como JSON")
            print("3. Guardar como CSV")
            print("4. Guardar como Reporte de Texto (.txt)")
            print("5. Guardar como Markdown (.md)")

            formato_op = input("Seleccione formato (1-5): ").strip()

            def progreso(actual, total, ioc):
                if actual % 5 == 0 or actual == total:
                    print(f"  Procesando [{actual}/{total}]: {ioc[:40]}...")

            print(f"\n⏳ Procesando archivo: {ruta_archivo}...")
            resultados = pipeline.process_file(ruta_archivo, on_progress=progreso)
            base_name = os.path.splitext(os.path.basename(ruta_archivo))[0]

            if formato_op == "1":
                print("\n" + IOCExporter.to_text_report(resultados))
            elif formato_op == "2":
                out_path = f"{base_name}_analisis.json"
                IOCExporter.to_json(resultados, out_path)
                print(f"✅ Guardado con éxito en: {out_path}")
                if is_in_colab():
                    from google.colab import files
                    files.download(out_path)
            elif formato_op == "3":
                out_path = f"{base_name}_analisis.csv"
                IOCExporter.to_csv(resultados, out_path)
                print(f"✅ Guardado con éxito en: {out_path}")
                if is_in_colab():
                    from google.colab import files
                    files.download(out_path)
            elif formato_op == "4":
                out_path = f"{base_name}_analisis.txt"
                IOCExporter.to_text_report(resultados, out_path)
                print(f"✅ Guardado con éxito en: {out_path}")
                if is_in_colab():
                    from google.colab import files
                    files.download(out_path)
            elif formato_op == "5":
                out_path = f"{base_name}_analisis.md"
                IOCExporter.to_markdown_table(resultados, out_path)
                print(f"✅ Guardado con éxito en: {out_path}")
                if is_in_colab():
                    from google.colab import files
                    files.download(out_path)

        elif opcion == "3":
            ioc = input("\nIngrese el IOC: ").strip()
            if not ioc:
                continue
            des = deobfuscate(ioc)
            norm = normalize(des) or des
            tipo = classify(norm)
            print("\n" + "-" * 40)
            print(f"Original     : {ioc}")
            print(f"Ofuscado     : {'Sí' if is_obfuscated(ioc) else 'No'}")
            print(f"Desofuscado  : {des}")
            print(f"Normalizado  : {norm}")
            print(f"Tipo         : {tipo}")
            print("-" * 40)

        elif opcion == "4":
            ioc = input("\nIngrese el IOC a desactivar (defang): ").strip()
            if ioc:
                print(f"Defanged: {defang(ioc)}")

        elif opcion == "5":
            print("\n👋 ¡Hasta pronto! Saliendo de Threat IOC Analyzer.")
            break
        else:
            print("❌ Opción no válida.")


def main():
    parser = argparse.ArgumentParser(
        description="Threat IOC Analyzer - Kit Forense de Indicadores de Compromiso"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando analyze
    p_analyze = subparsers.add_parser("analyze", help="Analiza un único IOC")
    p_analyze.add_argument("ioc", help="El IOC a analizar (URL, Dominio, IP, etc.)")
    p_analyze.add_argument("--skip-dns", action="store_true", help="Omitir resolución DNS")
    p_analyze.add_argument("--skip-rdap", action="store_true", help="Omitir consulta RDAP")
    p_analyze.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Formato de salida por consola"
    )

    # Comando batch
    p_batch = subparsers.add_parser("batch", help="Procesa un archivo de IOCs en lote")
    p_batch.add_argument("-i", "--input", required=True, help="Ruta al archivo .txt de entrada")
    p_batch.add_argument("-o", "--output", help="Ruta del archivo de salida")
    p_batch.add_argument(
        "--format",
        choices=["json", "csv", "text", "markdown"],
        default="json",
        help="Formato del archivo exportado"
    )
    p_batch.add_argument("--skip-dns", action="store_true", help="Omitir resolución DNS")
    p_batch.add_argument("--skip-rdap", action="store_true", help="Omitir consulta RDAP")

    # Comando defang
    p_defang = subparsers.add_parser("defang", help="Desactiva (defangs) un IOC de forma segura")
    p_defang.add_argument("ioc", help="El IOC a ofuscar")

    # Comando interactive
    subparsers.add_parser("interactive", help="Inicia la interfaz de consola interactiva")

    args = parser.parse_args()

    if not args.command or args.command == "interactive":
        run_interactive()
        return

    pipeline = IOCPipeline()

    if args.command == "analyze":
        res = pipeline.process_single(args.ioc, skip_dns=args.skip_dns, skip_rdap=args.skip_rdap)
        if args.format == "json":
            print(IOCExporter.to_json([res]))
        elif args.format == "markdown":
            print(IOCExporter.to_markdown_table([res]))
        else:
            print(IOCExporter.to_text_report([res]))

    elif args.command == "batch":
        if not os.path.exists(args.input):
            print(f"❌ Error: El archivo '{args.input}' no existe.", file=sys.stderr)
            sys.exit(1)

        results = pipeline.process_file(args.input, skip_dns=args.skip_dns, skip_rdap=args.skip_rdap)

        if args.format == "json":
            out = IOCExporter.to_json(results, args.output)
        elif args.format == "csv":
            out = IOCExporter.to_csv(results, args.output)
        elif args.format == "markdown":
            out = IOCExporter.to_markdown_table(results, args.output)
        else:
            out = IOCExporter.to_text_report(results, args.output)

        if args.output:
            print(f"✅ Análisis completado. Guardado en: {args.output}")
        else:
            print(out)

    elif args.command == "defang":
        print(defang(args.ioc))


if __name__ == "__main__":
    main()
