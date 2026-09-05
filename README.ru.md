# Claude Security Skills

Скиллы по безопасности для [Claude Code](https://claude.com/claude-code).
Поставьте их один раз и просите Claude обычными словами: найти утёкшие секреты
в репозитории, проверить питоновский код, погонять свой LLM на prompt injection,
разобрать HTTP-заголовки, JWT, Dockerfile, CORS или зависимости. Claude сам
выберет нужный скилл, запустит его и объяснит, что нашлось.

Всё работает на стандартной библиотеке Python: ставить нечего, наружу ничего не
уходит. Анализ идёт офлайн, в сеть лезут только те скиллы, которым нужен URL, и
только когда вы их об этом просите.

Python 3.9+, лицензия MIT. Другие языки: [English](README.md) · [Español](README.es.md)

## Скиллы

| Скилл | Что делает | Движок |
|-------|------------|--------|
| [secret-scanner](skills/secret-scanner) | Находит зашитые в код API-ключи, токены и приватные ключи по вендорным шаблонам вместе с анализом энтропии Шеннона, настроен на малое число ложных срабатываний | Свой движок энтропии |
| [sast-lite](skills/sast-lite) | Статический анализ Python по AST: инъекция команд, eval/exec, небезопасная десериализация, SQLi, слабая криптография, отключённый TLS — каждая находка с номером CWE | Обход AST |
| [prompt-injection-tester](skills/prompt-injection-tester) | Гоняет ваше собственное LLM-приложение по библиотеке пейлоадов с детектом канареек и выставляет устойчивость от 0 до 100 | Canary-харнесс |
| [http-sec-audit](skills/http-sec-audit) | Проверяет HTTP-заголовки безопасности и флаги cookie (CSP, HSTS, SameSite и прочие) и говорит, что именно поправить | urllib |
| [jwt-inspector](skills/jwt-inspector) | Разбирает и аудитит JWT (alg=none, слишком долгий срок жизни, гигиена claims) и офлайн подбирает слабые HMAC-секреты | HMAC и проверки |
| [dependency-check](skills/dependency-check) | Отмечает уязвимые и незакреплённые зависимости в `requirements.txt`, `package.json` и `pyproject.toml`; офлайн-база, при желании OSV.dev | Сопоставление версий |
| [dockerfile-scan](skills/dockerfile-scan) | Ловит опасное в Dockerfile: запуск от root, базовый образ `:latest`, `curl \| sh`, удалённый `ADD`, зашитые секреты | Парсер Dockerfile |
| [cors-auditor](skills/cors-auditor) | Разбирает настройки CORS: wildcard вместе с credentials, отражённый Origin, `null`-origin, слишком широкий список методов | Анализатор заголовков |

Каждый скилл самодостаточен, имеет свои тесты и завершается ненулевым кодом,
когда что-то нашёл, — то есть годится и как шаг в CI.

## Установка

Плагином, прямо из Claude Code:

```
/plugin marketplace add NovaCode37/claude-security-skills
/plugin install claude-security-skills
```

Все восемь скиллов приезжают вместе и обновляются вместе с маркетплейсом.

Либо скопировать руками, работает так же:

```bash
git clone https://github.com/NovaCode37/claude-security-skills.git
cp -r claude-security-skills/skills/* .claude/skills/
```

Копируйте в `~/.claude/skills/`, если хотите иметь их во всех проектах.
Перезапустите Claude Code, и он найдёт скиллы по файлам `SKILL.md`. Больше
ставить ничего не нужно ни при одном из способов.

## Как пользоваться

Просто спросите Claude:

| Вы говорите | Claude запускает |
|-------------|------------------|
| «Есть тут закоммиченные секреты?» | secret-scanner |
| «Проверь этот питоновский файл на уязвимости.» | sast-lite |
| «Мой ассистент можно сломать промптом?» | prompt-injection-tester |
| «Посмотри security-заголовки example.com.» | http-sec-audit |
| «Разбери этот JWT.» | jwt-inspector |
| «В зависимостях есть уязвимые?» | dependency-check |
| «Глянь мой Dockerfile.» | dockerfile-scan |
| «CORS у моего API нормально настроен?» | cors-auditor |

Каждый движок запускается и сам по себе, из командной строки:

```bash
python skills/secret-scanner/engine.py .            --json
python skills/sast-lite/analyzer.py src/            --min-severity high
python skills/prompt-injection-tester/attacker.py   --demo
python skills/http-sec-audit/audit.py https://example.com
python skills/jwt-inspector/inspector.py "<токен>"
python skills/dependency-check/checker.py requirements.txt
python skills/dockerfile-scan/scanner.py Dockerfile
python skills/cors-auditor/auditor.py https://api.example.com
```

Вот как выглядит запуск:

```console
$ python skills/secret-scanner/engine.py .
[secret-scanner] 2 potential secret(s) found:

  CRITICAL   src/config.py:14:18
             Stripe secret key [stripe-secret]  value=sk_l...k1L2 (len=32)
  HIGH       src/config.py:12:11
             AWS Access Key ID [aws-access-key-id]  value=AKIA...MPLE (len=20)

Summary: critical=1, high=1
```

## Тесты

```bash
pip install pytest
pytest skills/ -q
```

158 тестов, все офлайн, отрабатывают меньше чем за секунду.

## На чём это построено

- **Никаких зависимостей в рантайме.** Только стандартная библиотека Python
  3.9+, поэтому скиллы работают в закрытом CI и их несложно прочитать глазами.
- **Офлайн по умолчанию.** Логика анализа принимает данные и возвращает
  находки; выход в сеть — отдельная и явная вещь.
- **Мало ложных срабатываний.** Пороги энтропии, привязка к ключевым словам и
  списки заглушек убирают шум.
- **Дружит с CI.** Одинаковые коды возврата (`0` чисто, `1` есть находки,
  `2` ошибка) и `--json` у каждого скилла.
- **Безопасно по умолчанию.** Секреты в выводе маскируются, а наступательные
  скиллы предназначены для систем, которыми вы владеете или на тест которых у
  вас есть разрешение.

## Как поучаствовать

Новые скиллы и правила приветствуются. У открытых задач с меткой
[good first issue](https://github.com/NovaCode37/claude-security-skills/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
указано, какой файл править и что должно заработать, чтобы задача считалась
сделанной, — так что взяться можно, не читая весь код целиком. В
[CONTRIBUTING.md](CONTRIBUTING.md) лежит шаблон скилла и принятые соглашения.

## Право и этика

Эти инструменты предназначены для авторизованного тестирования безопасности,
обучения и защиты. Сканируйте только те системы и данные, которыми владеете или
на проверку которых у вас есть разрешение. За неправомерное использование
авторы ответственности не несут.

## Лицензия

[MIT](LICENSE)
