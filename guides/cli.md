# CLI guide

## Установка

Рекомендуемый путь для разработки и локального запуска:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e . -c constraints.txt
pii-leak-detector doctor
```

`requirements.txt` фиксирует прямые runtime-зависимости, а `constraints.txt` фиксирует проверенные транзитивные версии. Для обычной установки используйте обе части через `-c constraints.txt`.

Для коротких команд доступен алиас:

```bash
pld doctor
```

Системная зависимость для OCR:

```bash
brew install tesseract tesseract-lang
```

Для Linux используйте пакетный менеджер дистрибутива, например `apt install tesseract-ocr tesseract-ocr-rus`.

## Команды

### `scan`

Основная команда:

```bash
pii-leak-detector scan share --mode fast
```

Поддерживается старый стиль без слова `scan`:

```bash
pii-leak-detector share --mode normal
```

Полезные флаги:

| Флаг | Назначение |
|---|---|
| `--mode fast|normal|hard` | Выбрать профиль pipeline. |
| `--max-candidates N` | Ограничить candidate pool после triage. |
| `--max-ocr-files N` | Ограничить OCR-бюджет в hard. |
| `--risk-threshold N` | Изменить порог submit. |
| `--ml` | Включить Presidio/spaCy NER. |
| `--ml-max-files N` | Ограничить число файлов для ML/NER. |
| `--scan-only` | Только инвентаризация. |
| `--plan` | Показать планы извлечения. |
| `--extract-limit N` | Smoke-прогон на первых N кандидатах. |

### `doctor`

Проверяет окружение:

```bash
pii-leak-detector doctor
```

Команда показывает путь к активному `detector_settings.json`, наличие Python-библиотек и системного `tesseract`.

### `init-config`

Создает копию активных настроек:

```bash
pii-leak-detector init-config detector_settings.local.json
```

Перезапись:

```bash
pii-leak-detector init-config detector_settings.local.json --force
```

Использовать отдельный конфиг:

```bash
PII_DETECTOR_SETTINGS=detector_settings.local.json pii-leak-detector scan share --mode normal
```

## Частые сценарии

Быстрый submit:

```bash
pii-leak-detector scan share --mode fast
```

Более широкий submit без OCR:

```bash
pii-leak-detector scan share --mode normal --max-candidates 250
```

Hard без OCR, чтобы проверить triage и отчеты:

```bash
pii-leak-detector scan share --mode hard --max-ocr-files 0
```

Hard с ограниченным OCR:

```bash
pii-leak-detector scan share --mode hard --max-candidates 400 --max-ocr-files 40
```
