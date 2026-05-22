# Developer guide

## Локальная разработка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pii-leak-detector doctor
```

Быстрая проверка:

```bash
python -m py_compile settings.py main.py file_search.py extraction_planner.py extraction_runner.py text_extractors.py pii_detector.py risk_classifier.py
pii-leak-detector scan share --mode fast
pii-leak-detector scan share --mode normal
```

`hard` запускайте только осознанно: OCR может быть дорогим. 

Для диагностики:

```bash
pii-leak-detector scan share --mode hard --max-ocr-files 0
```

## Слои

| Слой | Файл | Правило изменения |
|---|---|---|
| CLI | `pii_leak_detector/cli.py`, `main.py` | Не добавлять detector-логику в wrapper. CLI только парсит команды и вызывает pipeline. |
| Settings | `settings.py`, `detector_settings.json` | Все пороги, веса и keyword-списки сначала добавлять сюда. |
| Scan | `file_search.py` | Только инвентаризация и распознавание типа файла. Без чтения содержимого. |
| Plan | `extraction_planner.py` | Решает, чем читать файл и где разрешить OCR. Без ПДн и риска. |
| Run | `extraction_runner.py`, `text_extractors.py`, `ocr_extractor.py` | Выполняет extraction и возвращает `TextBlock`. |
| Detect | `pii_detector.py`, `pii_ner.py` | Находит категории ПДн. Не решает, что отправлять в submit. |
| Risk | `risk_classifier.py` | Финальный score, объяснения, submit/review/risk reports. |

## Как добавлять параметр системы

1. Добавьте значение в `detector_settings.json` в подходящий раздел.
2. В коде получите его через `settings.get`, `settings.tuple_setting` или `settings.set_setting`.
3. Укажите fallback со старым значением, чтобы конфиг старой версии не ломал запуск.
4. Обновите [settings guide](settings.md), если параметр должен менять пользователь.
5. Прогоните `fast` и `normal`, сравните количество submit-строк и top rules в отчетах.

Пример:

```python
NEW_LIMIT = int(cfg.get("planner.new_limit", 10))
NEW_KEYWORDS = cfg.tuple_setting("risk.new_keywords")
```

## Как добавлять risk-правило

1. Добавьте вес в `risk.rule_scores`.
2. В `risk_classifier.py` используйте `_rule_score("rule_name", default)`.
3. Добавьте `RiskRuleHit` с понятной причиной.
4. Проверьте, что правило видно в `risk_report_*.md` и `pipeline_report_*.md`.

Паттерн:

```python
if condition:
    delta = _rule_score("new_rule", 25)
    score += delta
    hits.append(RiskRuleHit("new_rule", delta, "Короткое объяснение для отчета."))
```

Не добавляйте dataset-only правила вида "если путь ровно X". 

Правило должно описывать переносимый признак: тип данных, структуру таблицы, контекст хранения, формат или рискованный набор категорий.

## Как добавлять extractor

1. Добавьте функцию в `text_extractors.py`, возвращающую `List[TextBlock]`.
2. Зарегистрируйте ее в `extraction_runner.EXTRACTORS`.
3. В `extraction_planner.py` добавьте стратегию или шаг `ExtractionStep`.
4. Для дорогих операций используйте `escalation_steps`, а не primary.
5. Лимиты и триггеры вынесите в `detector_settings.json`.

`TextBlock` должен сохранять происхождение: файл, метод, страницу/лист/строки и технические metadata. 

Это нужно risk-слою для объяснимости.

## Как менять CLI

`pii_leak_detector/cli.py` отвечает за продуктовые команды:

- `scan` делегирует в `main.main(argv)`;
- `doctor` проверяет окружение;
- `init-config` копирует настройки.

`main.py` сохраняет legacy-запуск и содержит орекестрацию для pipeline. 

Если добавляете новый режим, сначала добавьте его в `detector_settings.json`, затем проверьте `MODE_DEFAULTS`.

## Документация

Обновляйте markdown вместе с кодом:

- новый флаг CLI - `guides/cli.md`;
- новый параметр конфига - `guides/settings.md`;
- изменение pipeline - `guides/pipeline.md`;
- изменение risk-логики - `guides/risk_classifier.md`.

