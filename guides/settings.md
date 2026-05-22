# Settings guide

`detector_settings.json` - единая точка управления поведением системы. Менять числа, списки keyword-ов и пороги нужно здесь, а не в Python-коде.

Активный файл определяется в таком порядке:

1. `PII_DETECTOR_SETTINGS=/path/to/settings.json`.
2. `detector_settings.json` в текущей рабочей директории.
3. `detector_settings.json` рядом с `settings.py` в репозитории.
4. Файл, установленный вместе с пакетом.

Проверить активный путь:

```bash
pii-leak-detector doctor
```

## Разделы

### `mode_defaults`

Описывает режимы `fast`, `normal`, `hard`.

Ключевые параметры:

| Параметр | Влияние |
|---|---|
| `submit` | Куда писать итоговый `.txt`. |
| `risk_report` | Куда писать risk-debug отчет. |
| `pipeline_report` | Куда писать отчет по стадиям pipeline. |
| `review_report` | Куда писать кандидатов для ручной проверки. |
| `use_ner` | Включать ли ML/NER по умолчанию. |
| `include_escalations` | Разрешать ли OCR/escalation steps. |
| `max_candidates` | Лимит файлов после triage. |
| `triage_min_score` | Минимальный cheap-score для попадания в candidate pool. |

### `runtime_defaults`

Глобальные runtime-лимиты:

| Параметр | Влияние |
|---|---|
| `max_ocr_files` | Дефолтный OCR-бюджет hard mode. |
| `ml_max_files` | Дефолтный лимит файлов для ML/NER. |
| `review_floor` | Нижняя граница попадания в review report. |

### `triage`

Дешевый отбор до чтения содержимого файлов.

| Параметр | Влияние |
|---|---|
| `bucket_caps` | Сколько файлов брать из групп `text_table`, `document`, `web`, `binary_media`, `ocr_media`. |
| `family_scores` | Базовый score по семейству файла. |
| `hard_family_score_overrides` | Переопределения family score для hard. |
| `extension_scores` | Score по расширению. |
| `signal_scores` | Boost/penalty за контекст пути и имени. |
| `personal_keywords` | Слова, повышающие вероятность персонального контекста. |
| `export_keywords` | Слова, повышающие вероятность выгрузки/дампа. |
| `low_value_export_names` | Имена, которые обычно снижают ценность выгрузки. |
| `public_context_keywords` | Публичный/деловой контекст, снижающий triage score. |
| `fast_explicit_name_keywords` | Узкие сигналы, разрешающие отдельные docs/web в fast. |
| `ocr_candidate_scores` | Ранжирование файлов внутри hard OCR budget. |

Правило: повышайте `signal_scores` и bucket caps, если recall важнее скорости. Снижайте их, если появляется много FP и pipeline тратит время на публичный мусор.

### `planner`

Настраивает маршрутизацию extraction/OCR:

| Параметр | Влияние |
|---|---|
| `low_confidence_threshold` | Когда показывать warning по типу файла. |
| `tiny_file_bytes` | Граница почти пустого файла. |
| `small_image_bytes` | Маленькие изображения без подозрительного имени пропускаются. |
| `pdf_ocr_max_pages` | Максимум страниц PDF для OCR escalation. |
| `docx_ocr_max_images` | Максимум embedded images в DOCX. |
| `presentation_ocr_max_images` | Максимум embedded images в презентации. |
| `video_max_frames` | Максимум кадров видео для OCR. |
| `high_ocr_dir_keywords` | Папки, где OCR-контекст считается более подозрительным. |
| `suspicious_name_keywords` | Имя файла выглядит как scan/passport/form/dump. |
| `business_context_keywords` | Имя файла выглядит как нормальный деловой документ. |

### `risk`

Финальный скоринг и submit.

| Параметр | Влияние |
|---|---|
| `default_submit_threshold` | Score, начиная с которого файл попадает в submit. |
| `risk_level_high` | Граница уровня `high`. |
| `risk_level_review` | Граница уровня `review`. |
| `recommendation_priority` | Граница приоритетной ручной проверки. |
| `no_pii_score_cap` | Верхний cap для файлов без найденных ПДн. |
| `category_weights` | Базовый вклад категорий ПДн. |
| `rule_scores` | Веса конкретных boost/suppress правил. |
| `suspicious_path_score` | Формула вклада подозрительных keyword-ов в пути. |
| `benign_path_keywords` | Деловые/публичные слова для снижения score. |
| `business_*_categories` | Наборы категорий, считающиеся бизнес-контекстом. |
| `billing_full_dump_contexts` | Контексты, где billing/full не должен подавляться как обычная логистика. |
| `public_structured_noise_names` | Структурные файлы из публичного контекста, которые чаще шум. |
| `site_dump_contexts` | Контексты web/site dumps для suppress без профиля физлица. |

## Как тюнить без угадывания датасета

1. Смотрите `review_report_*.md`, а не только `submit_*.txt`.
2. Если нужный класс файлов есть в review, снижайте `default_submit_threshold` или повышайте конкретные `rule_scores`.
3. Если нужные файлы не дошли до extraction, меняйте `triage`: `bucket_caps`, `triage_min_score`, `signal_scores`.
4. Если FP уже в submit, сначала ищите suppress-правило в `risk.rule_scores`, потом корректируйте keyword-списки.
5. Для hard сначала ставьте `--max-ocr-files 0`, проверяйте candidate pool, затем постепенно включайте OCR budget.

После изменения настроек прогоняйте:

```bash
python -m py_compile settings.py main.py extraction_planner.py risk_classifier.py
pii-leak-detector scan share --mode fast
pii-leak-detector scan share --mode normal
```
