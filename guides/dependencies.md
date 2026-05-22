# Dependencies guide

В проекте используются pinned зависимости. Это важно, потому что OCR/PDF/ML-библиотеки часто ломают поведение при minor-обновлениях.

## Файлы

| Файл | Назначение |
|---|---|
| `requirements.txt` | Прямые runtime-зависимости проекта, все с точными версиями. |
| `requirements-dev.txt` | Прямые зависимости для разработки. |
| `constraints.txt` | Проверенный lock транзитивных зависимостей из рабочей среды. |
| `setup.py` | Читает `requirements.txt` и `requirements-dev.txt`, чтобы CLI-установка не расходилась с requirements. |

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e . -c constraints.txt
pii-leak-detector doctor
```

Для разработки:

```bash
pip install -e ".[dev]" -c constraints.txt
```

## Runtime-зависимости

| Пакет | Зачем нужен |
|---|---|
| `filetype` | Определение MIME/типа файла. |
| `PyMuPDF` | Чтение PDF и рендер страниц для OCR. |
| `numpy` | Работа с изображениями/кадрами. |
| `opencv-python-headless` | Предобработка изображений и видео для OCR. |
| `Pillow` | Чтение и нормализация изображений. |
| `pyarrow` | Чтение Parquet. |
| `pytesseract` | Python-обертка над системным Tesseract. |
| `python-pptx` | Чтение PPTX и embedded images. |
| `presidio-analyzer` | Опциональный ML/NER слой. |
| `spacy` | NLP backend для Presidio. |
| `xx-ent-wiki-sm` | spaCy-модель, которую использует `pii_ner.py`. |

## Системные зависимости

`pytesseract` не содержит сам OCR-движок. Для OCR нужен системный бинарь:

```bash
brew install tesseract tesseract-lang
```

Linux пример:

```bash
sudo apt install tesseract-ocr tesseract-ocr-rus
```

Проверка:

```bash
pii-leak-detector doctor
```

## Как обновлять версии

1. Обновите пакет в отдельном venv.
2. Прогоните `doctor`, `fast`, `normal`; для OCR отдельно smoke `hard --max-ocr-files N`.
3. Обновите pin в `requirements.txt`.
4. Обновите `constraints.txt` по результатам проверенной среды.
5. Не добавляйте транзитивные пакеты в `requirements.txt`, если код их напрямую не импортирует.
