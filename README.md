# 🛡️ Threat IOC Analyzer
### Automated Threat Intelligence & Forensic IOC Lifecycle Toolkit

[![Python Versions](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Cristiangarcia913/threat-ioc-analyzer/blob/main/notebooks/Threat_IOC_Analyzer.ipynb)
[![CI Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![DFIR Category](https://img.shields.io/badge/category-DFIR%20%26%20CTI-red.svg)]()

**Threat IOC Analyzer** es un kit de herramientas forenses de nivel profesional diseñado y desarrollado por **Cristian García** ([@Cristiangarcia913](https://github.com/Cristiangarcia913)) para procesar, homologar, resolver y enriquecer **Indicadores de Compromiso (IOCs)** en tareas de Respuesta a Incidentes (DFIR) y Ciberinteligencia de Amenazas (CTI).

Construido como un paquete modular de Python con interfaz CLI, suite de pruebas unitarias y cuaderno interactivo para Google Colab y Jupyter Lab.

---

## 📌 Tabla de Contenidos
- [Arquitectura Forense (5 Fases)](#-arquitectura-forense-5-fases)
- [Características Principales](#-características-principales)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
  - [1. Modo Interactivo](#1-modo-interactivo)
  - [2. Línea de Comandos (CLI)](#2-línea-de-comandos-cli)
  - [3. Como Librería en Python](#3-como-librería-en-python)
  - [4. En Google Colab / Jupyter](#4-en-google-colab--jupyter)
- [Tipos de IOC Soportados](#-tipos-de-ioc-soportados)
- [Formatos de Exportación](#-formatos-de-exportación)
- [Caso de Estudio: Muestra Botnet Mirai](#-caso-de-estudio-muestra-botnet-mirai)
- [Tests y Calidad de Código](#-tests-y-calidad-de-código)
- [Autor](#-autor)
- [Licencia](#-licencia)

---

## 🔬 Arquitectura Forense (5 Fases)

El ciclo de procesamiento implementa un pipeline estricto en cascada:

```
[ IOC en Bruto / Defanged ]
           │
           ▼
┌───────────────────────────┐
│ 1. Desofuscación          │ ➔ Revierte hxxp://, [.], (dot), [:], etc.
└──────────┬────────────────┘
           │
           ▼
┌───────────────────────────┐
│ 2. Normalización RFC      │ ➔ Decodifica percent-encoding, IP ports, minúsculas
└──────────┬────────────────┘
           │
           ▼
┌───────────────────────────┐
│ 3. Clasificación Taxonómica│ ➔ IPv4, IPv6, Dominio, URL, Email, Hashes
└──────────┬────────────────┘
           │
           ▼
┌───────────────────────────┐
│ 4. Resolución DNS         │ ➔ A (IPv4), AAAA (IPv6), PTR (Inversa)
└──────────┬────────────────┘
           │
           ▼
┌───────────────────────────┐
│ 5. Enriquecimiento RDAP   │ ➔ Propietario, Registrador, Fechas y Abuse Email
└──────────┬────────────────┘
           │
           ▼
[ Reportes JSON / CSV / TXT / Markdown ]
```

---

## 🚀 Características Principales

- **Desofuscación Completa (Defanging / Refanging):** Convierte formatos ofuscados habituales en reportes de amenazas a formatos analizables estándar, y permite volver a ofuscarlos para compartir en tickets o informes con seguridad.
- **Normalización Inteligente:** Extracción y limpieza según RFC, separando direcciones IP de sus puertos (`196.251.80.5:3778`), limpiando esquemas y decodificando URLs.
- **Resolución DNS Autónoma:** Extrae automáticamente el host o IP resoluble incluso si el indicador de entrada es una URL completa con parámetros o un puerto.
- **Cliente RDAP Multi-RIR (RFC 7480-7484):** No depende de un único registro regional; consulta mediante bootstrap universal a RIPE, ARIN, APNIC, LACNIC y Verisign para obtener titularidad, fechas de alta/expiración y correos de contacto por abuso.
- **Multiplataforma y Desacoplado:** Funciona como aplicación CLI en terminales Linux/macOS/Windows, como librería de Python y en notebooks de Jupyter y Google Colab sin errores de dependencias ausentes.
- **Exportación Flexible:** Informes en JSON estructurado, CSV para Excel/SIEM, Markdown para documentación y texto plano pericial.

---

## 📦 Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/Cristiangarcia913/threat-ioc-analyzer.git
cd threat-ioc-analyzer
```

### 2. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 3. Instalar en modo editable (opcional para comando global `threat-ioc`)
```bash
pip install -e .
```

---

## 💻 Uso Rápido

### 1. Modo Interactivo
Ejecuta el asistente interactivo por menú:
```bash
python -m ioc_analyzer
```

### 2. Línea de Comandos (CLI)

#### Analizar un IOC individual
```bash
python -m ioc_analyzer analyze "hxxps://malware-drop[.]com/sample.exe"
```

#### Salida formateada en Markdown o JSON
```bash
python -m ioc_analyzer analyze "rebirthbot[.]icu" --format markdown
python -m ioc_analyzer analyze "185[.]203[.]118[.]55" --format json
```

#### Procesar archivo de IOCs en lote (Batch)
```bash
python -m ioc_analyzer batch -i examples/mirai_botnet_iocs.txt -o reporte_mirai.json --format json
python -m ioc_analyzer batch -i examples/mirai_botnet_iocs.txt -o reporte_mirai.csv --format csv
```

#### Ofuscar de forma segura (Defang) para enviar por email o ticket
```bash
python -m ioc_analyzer defang "http://malicious-command-center.net"
# Salida: hxxp://malicious-command-center[.]net
```

---

### 3. Como Librería en Python

```python
from ioc_analyzer import analyze, deobfuscate, normalize, classify

# 1. Pipeline completo en una sola línea
resultado = analyze("hxxp://93[.]123[.]85[.]239/mirai[.]arm")

print(resultado["normalized"])  # http://93.123.85.239/mirai.arm
print(resultado["type"])        # URL
print(resultado["dns"]["A"])    # Registros IPv4
print(resultado["rdap"])        # Información de registro y abuso

# 2. Uso modular
limpio = deobfuscate("evil-c2[.]org")
tipo = classify(limpio)
print(f"Indicador: {limpio} ({tipo})")
```

---

### 4. En Google Colab / Jupyter

Abre directamente el cuaderno [notebooks/Threat_IOC_Analyzer.ipynb](notebooks/Threat_IOC_Analyzer.ipynb) en Google Colab o tu entorno Jupyter local. Incluye:
- Interfaz gráfica con `ipywidgets` y botones de acción.
- Carga de archivos interactiva.
- Pruebas guiadas paso a paso.

---

## 🏷️ Tipos de IOC Soportados

| Tipo | Ejemplo de Entrada | Detección y Enriquecimiento |
|---|---|---|
| **URL** | `hxxp://evil[.]com/drop.sh` | Extrae host, analiza DNS del dominio y RDAP |
| **Dominio** | `miraicnc[.]ddns[.]net` | Registros A, AAAA, CNAME y RDAP |
| **IPv4** | `185[.]203[.]118[.]55` | Resolución PTR (inversa) y titularidad RIR |
| **IPv4 con Puerto** | `196[.]251[.]80[.]5:3778` | Separa host y puerto, analiza IP |
| **IPv6** | `2001:db8::1` | Resolución PTR inversa y rango IPv6 |
| **Hashes** | `e3b0c44298fc1c14...` | Identificación de algoritmo (MD5, SHA-1, SHA-256) |
| **Email** | `phishing[@]bank[.]com` | Identificación para investigación de spoofing |

---

## 📊 Formatos de Exportación

- **JSON (`--format json`):** Metadatos de auditoría ISO-8601, estructurado para ingestión en Elastic, Splunk o OpenCTI.
- **CSV (`--format csv`):** Filas homogéneas con campos clave para hojas de cálculo e informes forenses.
- **Markdown (`--format markdown`):** Tablas limpias listas para adjuntar en Pull Requests, GitHub Issues o informes periciales.
- **Texto Plano (`--format text`):** Formato pericial legible por humanos con separadores y timestamps.

---

## 🕵️ Caso de Estudio: Muestra Botnet Mirai

En la carpeta [`examples/mirai_botnet_iocs.txt`](examples/mirai_botnet_iocs.txt) se incluye una muestra real de indicadores de la botnet Mirai, compuesta por:
- URLs de descarga de binarios MIPS / ARM (`mirai.m68k`, `mirai.arm4`).
- Dominios C2 (`rebirthbot.icu`, `miraicnc.ddns.net`).
- Direcciones IP con puertos de escaneo Telnet/C2 (`196.251.80.5:3778`).

Ejecución de prueba con el dataset:
```bash
python -m ioc_analyzer batch -i examples/mirai_botnet_iocs.txt -o mirai_reporte.md --format markdown
```

---

## 🧪 Tests y Calidad de Código

El proyecto cuenta con una batería de tests unitarios que cubre todas las fases del ciclo de vida forense:

```bash
python -m unittest discover -s tests -v
```

Resultado:
```text
test_classify_domain ... ok
test_classify_email ... ok
test_classify_hashes ... ok
test_classify_ip ... ok
test_classify_url ... ok
test_defang ... ok
test_dots_deobfuscation ... ok
test_ip_deobfuscation ... ok
test_is_obfuscated ... ok
test_mirai_samples_deobfuscation ... ok
test_protocol_deobfuscation ... ok
test_extract_target ... ok
test_resolve_localhost_ip ... ok
test_normalize_domain ... ok
test_normalize_ip ... ok
test_normalize_url ... ok
test_pipeline_mirai_samples ... ok
test_pipeline_single_ioc_no_network ... ok

Ran 18 tests in 0.009s - OK
```

---

## 👤 Autor

- **Cristian García** ([@Cristiangarcia913](https://github.com/Cristiangarcia913))

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.
