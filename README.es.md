# Habilidades de Seguridad de Claude

<div align="center">

<img src="assets/banner.svg" alt="Claude Security Skills" width="100%">

<br/>

**Habilidades de Claude Code [Claude Code](https://claude.com/claude-code) listas para producción para seguridad ofensiva y defensiva.**

Encuentra secretos filtrados, ejecuta SAST ligero, prueba prompt injection en LLM, y audita encabezados HTTP, JWT y dependencias desde solicitudes en lenguaje natural dentro de Claude Code.

[![CI](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-114%20passing-brightgreen)](#tests)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Dependencias en tiempo de ejecución](https://img.shields.io/badge/runtime%20deps-0-success)](#design-principles)
[![License: MIT](https://img.shields.io/badge/license-MIT-black)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-orange)](CONTRIBUTING.md)

[**Instalar**](#install) · [**Habilidades**](#the-skills) · [**Uso**](#usage) · [**Cómo funciona**](#how-it-works) · [**Contribuir**](CONTRIBUTING.md)

</div>

---

## ¿Qué es esto?

Estas habilidades de Claude Code encapsulan capacidades de seguridad especializadas para que puedas invocarlas desde una sola instrucción en lenguaje natural.

Después de instalar el paquete, pide cosas como:

> 💬 *"Escanea este repositorio en busca de secretos filtrados."*
> 💬 *"Haz un red-team de mi chatbot para prompt injection y dame una puntuación."*
> 💬 *"Audita un repositorio Python en busca de vulnerabilidades."*

Claude selecciona la habilidad correcta, ejecuta el motor y resume los resultados con sugerencias de corrección.

## Habilidades

| Habilidad | Qué hace | Motor |
|----------|----------|-------|
| [**secret-scanner**](skills/secret-scanner) | Detecta llaves API, tokens y claves privadas con regex + análisis de entropía, minimizando falsos positivos | Motor de entropía propio |
| [**sast-lite**](skills/sast-lite) | Análisis estático básico de Python para inyección de comandos, eval/exec, deserialización insegura, SQLi, crypto débil y TLS deshabilitado | Recorrido de AST |
| [**prompt-injection-tester**](skills/prompt-injection-tester) | Prueba tu LLM con payloads clasificados y marcadores de éxito, devuelve resiliencia 0–100 | Harness canario |
| [**http-sec-audit**](skills/http-sec-audit) | Audita encabezados de seguridad HTTP y cookies (CSP, HSTS, SameSite, etc.) con recomendaciones | urllib + lógica de núcleo |
| [**jwt-inspector**](skills/jwt-inspector) | Decodifica y audita JWT (alg=none, expiración débil, higiene de claims) y fuerza secretos HMAC débiles | HMAC + reglas |
| [**dependency-check**](skills/dependency-check) | Detecta dependencias vulnerables/no fijadas en `requirements.txt` / `package.json` | Analizador de versiones |

## Uso

```bash
python skills/secret-scanner/engine.py .            --json
python skills/sast-lite/analyzer.py src/            --min-severity high
python skills/prompt-injection-tester/attacker.py   --demo
python skills/http-sec-audit/audit.py https://example.com
python skills/jwt-inspector/inspector.py "<token>"
python skills/dependency-check/checker.py requirements.txt
```

## Pruebas

```bash
pip install pytest
pytest skills/ -q
```

## Principios de diseño

- **Sin dependencias en tiempo de ejecución.** Funciona solo con la biblioteca estándar de Python 3.9+.
- **Núcleo offline-first.** El análisis puede ejecutarse sin red; cualquier función de red es opcional y explícita.
- **Falsos positivos bajos.** Umbral de entropía, anclas de palabras clave y listas blancas de placeholders reducen ruido.
- **Amigable con CI.** Códigos de salida coherentes (`0` limpio / `1` hallazgos / `2` error).

## Contribuciones

Nuevas habilidades, reglas y mejoras de documentación son bienvenidas.

- Revisa [CONTRIBUTING.md](CONTRIBUTING.md)
- Consulta problemas etiquetados como [good first issues](docs/GOOD_FIRST_ISSUES.md)
- Abre una discusión en [GitHub Discussions](https://github.com/NovaCode37/claude-security-skills/discussions) si quieres proponer algo nuevo.
