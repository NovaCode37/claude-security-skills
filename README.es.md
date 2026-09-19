# Claude Security Skills

[![CI](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NovaCode37/claude-security-skills?style=flat-square&color=7c5cfc)](https://github.com/NovaCode37/claude-security-skills/releases)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

Habilidades de seguridad para [Claude Code](https://claude.com/claude-code).
Instálalas una vez y pídele a Claude, en lenguaje corriente, que busque secretos
filtrados en un repositorio, revise código Python, someta tu LLM a pruebas de
prompt injection, o audite cabeceras HTTP, JWT, Dockerfiles, CORS y
dependencias. Claude elige la habilidad adecuada, la ejecuta y explica lo que
encontró.

Todo funciona con la biblioteca estándar de Python: no hay paquetes que
instalar y nada sale de tu máquina. El análisis es offline; solo las habilidades
que necesitan una URL usan la red, y únicamente cuando se lo pides.

Python 3.9+, licencia MIT. Otros idiomas: [English](README.md) · [Русский](README.ru.md)

```console
$ python skills/secret-scanner/engine.py .
[secret-scanner] 2 potential secret(s) found:

  CRITICAL   src/config.py:14:18
             Stripe secret key [stripe-secret]  value=sk_l...k1L2 (len=32)
  HIGH       src/config.py:12:11
             AWS Access Key ID [aws-access-key-id]  value=AKIA...MPLE (len=20)

Summary: critical=1, high=1
```

**Novedades en 1.1.0:** secret-scanner reconoce claves de Hugging Face,
Replicate, Groq, Cohere y DigitalOcean, sast-lite señala el uso de `random`
para generar tokens, y http-sec-audit incorpora `--advisory` para el
aislamiento cross-origin. Detalles en el [changelog](CHANGELOG.md).

## Las habilidades

| Habilidad | Qué hace | Motor |
|-----------|----------|-------|
| [secret-scanner](skills/secret-scanner) | Encuentra llaves de API, tokens y claves privadas escritas en el código, combinando patrones de proveedores con análisis de entropía de Shannon, ajustado para dar pocos falsos positivos | Motor de entropía propio |
| [sast-lite](skills/sast-lite) | Análisis estático de Python sobre el AST: inyección de comandos, eval/exec, deserialización insegura, SQLi, criptografía débil, TLS desactivado — cada hallazgo con su CWE | Recorrido del AST |
| [prompt-injection-tester](skills/prompt-injection-tester) | Somete tu propia aplicación LLM a una biblioteca de payloads clasificados con detección de canarios, y puntúa la resistencia de 0 a 100 | Harness de canarios |
| [http-sec-audit](skills/http-sec-audit) | Revisa las cabeceras de seguridad HTTP y los flags de las cookies (CSP, HSTS, SameSite y demás) e indica qué corregir | urllib |
| [jwt-inspector](skills/jwt-inspector) | Decodifica y audita JWT (alg=none, expiración demasiado larga, higiene de claims) y descifra secretos HMAC débiles sin conexión | HMAC y comprobaciones |
| [dependency-check](skills/dependency-check) | Señala dependencias vulnerables y sin fijar en `requirements.txt`, `package.json` y `pyproject.toml`; base offline y, si quieres, OSV.dev | Comparador de versiones |
| [dockerfile-scan](skills/dockerfile-scan) | Detecta patrones inseguros en Dockerfile: ejecución como root, imagen base `:latest`, `curl \| sh`, `ADD` remoto, secretos incrustados | Analizador de Dockerfile |
| [cors-auditor](skills/cors-auditor) | Audita la configuración CORS: comodín junto a credenciales, Origin reflejado, origen `null`, métodos demasiado amplios | Analizador de cabeceras |

Cada habilidad es autónoma, trae sus propias pruebas y termina con código
distinto de cero cuando encuentra algo, así que también sirve como paso de CI.

## Instalación

Como plugin, desde dentro de Claude Code:

```
/plugin marketplace add NovaCode37/claude-security-skills
/plugin install claude-security-skills
```

Las ocho habilidades llegan juntas y se actualizan con el marketplace.

O cópialas a mano, que funciona igual:

```bash
git clone https://github.com/NovaCode37/claude-security-skills.git
cp -r claude-security-skills/skills/* .claude/skills/
```

Usa `~/.claude/skills/` si las quieres en todos tus proyectos. Reinicia Claude
Code y las descubrirá a partir de cada `SKILL.md`. No hay nada más que instalar
en ninguno de los dos casos.

Si acaban ganándose un sitio en tu configuración, una estrella ayuda a que las
encuentre la siguiente persona. La instalación pasa por un clon, así que la
estrella es lo único que ve el resto.

## Uso

Basta con pedírselo a Claude:

| Tú dices | Claude ejecuta |
|----------|----------------|
| «¿Hay secretos subidos aquí?» | secret-scanner |
| «Revisa la seguridad de este archivo Python.» | sast-lite |
| «¿Se puede romper mi asistente con un prompt?» | prompt-injection-tester |
| «Mira las cabeceras de seguridad de example.com.» | http-sec-audit |
| «Decodifica y audita este JWT.» | jwt-inspector |
| «¿Tengo dependencias vulnerables?» | dependency-check |
| «Revisa mi Dockerfile.» | dockerfile-scan |
| «¿El CORS de mi API es seguro?» | cors-auditor |

Cada motor también se ejecuta por su cuenta desde la línea de comandos:

```bash
python skills/secret-scanner/engine.py .            --json
python skills/sast-lite/analyzer.py src/            --min-severity high
python skills/prompt-injection-tester/attacker.py   --demo
python skills/http-sec-audit/audit.py https://example.com --min-severity high
python skills/jwt-inspector/inspector.py "<token>"
python skills/dependency-check/checker.py requirements.txt
python skills/dockerfile-scan/scanner.py Dockerfile
python skills/cors-auditor/auditor.py https://api.example.com
```

## En CI

Los motores son los mismos archivos que ejecuta Claude, así que un pipeline
puede llamarlos directamente. No hay nada que instalar, por eso no hay paso
`pip install`:

```yaml
name: security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Obtener las habilidades
        run: git clone --depth 1 https://github.com/NovaCode37/claude-security-skills .skills
      - name: Analizar
        run: |
          python .skills/skills/secret-scanner/engine.py .
          python .skills/skills/sast-lite/analyzer.py . --min-severity high
          python .skills/skills/dockerfile-scan/scanner.py Dockerfile
```

Cada motor termina con `1` cuando reporta algo, así que el paso falla ante un
hallazgo. Usa `--min-severity` para decidir qué merece romper la compilación.

## Pruebas

```bash
pip install pytest
pytest skills/ -q
```

227 pruebas, todas offline, en menos de un segundo.

## Cómo está construido

- **Sin dependencias en tiempo de ejecución.** Solo la biblioteca estándar de
  Python 3.9+, así que las habilidades funcionan en CI aislado y son fáciles de
  leer y auditar.
- **Offline por defecto.** La lógica de análisis recibe datos y devuelve
  hallazgos; el acceso a la red es opcional y explícito.
- **Pocos falsos positivos.** Umbrales de entropía, anclaje por palabras clave
  y listas de marcadores de posición mantienen bajo el ruido.
- **Pensado para CI.** Códigos de salida coherentes (`0` limpio, `1` hallazgos,
  `2` error) y `--json` en todas las habilidades. Todo hallazgo reportado hace
  fallar la compilación, sea cual sea su severidad; las habilidades que generan
  ruido informativo aceptan `--min-severity` para que cada pipeline suba el
  listón.
- **Seguro por defecto.** Los secretos se enmascaran en la salida, y las
  habilidades ofensivas están pensadas para sistemas que te pertenecen o que
  tienes permiso para probar.

## Contribuir

Se agradecen nuevas habilidades y reglas. Las incidencias abiertas con la
etiqueta [good first issue](https://github.com/NovaCode37/claude-security-skills/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
indican qué archivo tocar y qué debe pasar para darlas por terminadas, así que
puedes resolver una sin leer todo el código antes.
[CONTRIBUTING.md](CONTRIBUTING.md) tiene la plantilla de habilidad y las
convenciones.

## También de este proyecto

[PRISM](https://github.com/NovaCode37/Prism-platform) — una plataforma OSINT autoalojada con panel web: dominios, IPs, correos, teléfonos y nombres de usuario en más de 22 módulos, con puntuación de exposición, grafo de entidades e informes en HTML y PDF.

## Aspectos legales

Estas herramientas son para pruebas de seguridad autorizadas, aprendizaje y
trabajo defensivo. Analiza únicamente sistemas y datos que te pertenezcan o
para los que tengas permiso. Los mantenedores no se responsabilizan del mal uso.

## Licencia

[MIT](LICENSE)
