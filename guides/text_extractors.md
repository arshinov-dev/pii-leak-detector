# Базовые извлекатели текста

## Назначение

`text_extractors.py` превращает файлы разных форматов в единый поток `TextBlock`.

Этот слой не ищет ПДн, не классифицирует риск и не запускает OCR. Он выполняет
только дешевые способы извлечения текста, которые должны предшествовать OCR:

- прямое чтение TXT/Markdown;
- очистка HTML;
- структурный парсинг CSV/TSV и JSON;
- цифровой текст PDF через PyMuPDF;
- DOCX через ZIP/XML без `python-docx`;
- RTF как текстовый fallback;
- XLSX через ZIP/XML без `openpyxl`.

Если формат требует отдельной зависимости или конвертера, extractor возвращает
диагностический `TextBlock` с пустым текстом и предупреждением. Pipeline при этом
не падает.

## Контракт `TextBlock`

`TextBlock` описан в `text_blocks.py`.

Основные поля:

| Поле | Что означает |
|---|---|
| `file_path` | Исходный файл. |
| `source_type` | Логический источник: `pages`, `table`, `document`, `html`. |
| `block_index` | Номер блока внутри файла. |
| `page_or_sheet` | Страница PDF, лист XLSX, диапазон строк или часть DOCX. |
| `extraction_method` | Имя extractor-а. |
| `text` | Извлеченный текст. |
| `warnings` | Предупреждения по блоку. |
| `metadata` | Технические детали, например кодировка или диапазон строк. |

## Runner

`extraction_runner.py` исполняет primary-шаги из `ExtractionPlan`.

Он запускает только зарегистрированные дешевые извлекатели:

- `plain_text_extractor`;
- `html_text_extractor`;
- `csv_extractor`;
- `json_extractor`;
- `parquet_extractor`;
- `spreadsheet_extractor`;
- `pdf_text_extractor`;
- `docx_text_extractor`;
- `rtf_text_extractor`.

OCR-эскалации, image prefilter, video, archive и legacy Office пока фиксируются
как пропущенные или диагностические шаги.

## CLI

Smoke-прогон на первых N планах:

```bash
pii-leak-detector scan share --extract --extract-limit 50
```

Можно совместить со сводкой планов:

```bash
pii-leak-detector scan share --plan --extract --extract-limit 50
```

Полный запуск `--extract` по всему датасету возможен, но для больших PDF и
таблиц может занимать заметное время.
