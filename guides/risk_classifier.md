# Risk classifier guide

`risk_classifier.py` превращает признаки ПДн и контекст extraction в финальный score, уровень риска, объяснения и `submit_*.txt`.

**Этот слой не ищет ПДн сам**. Он получает:

- `ExtractionPlan` - family, extension, strategy, OCR/context metadata;
- `ExtractionRunResult` - что удалось извлечь и какие шаги пропущены;
- `PiiFileResult` - категории ПДн и количества;
- активные настройки из `detector_settings.json -> risk`.

## Контракты

### `RiskAssessment`

| Поле | Что означает |
|---|---|
| `file_path` | Полный путь на диске. |
| `submit_path` | Путь от корня scan folder, формат для бота. |
| `score` | Итоговый риск-score. |
| `level` | `low`, `review`, `submit`, `high`. |
| `categories` | Категории ПДн и количества. |
| `rule_hits` | Правила, которые повлияли на score. |
| `recommendation` | Рекомендация для ручной проверки. |
| `document_type` | Предполагаемый тип документа/массива. |

### `RiskRuleHit`

| Поле | Что означает |
|---|---|
| `rule` | Машинное имя правила. |
| `score_delta` | Вклад в score, положительный или отрицательный. |
| `reason` | Человеческое объяснение для report. |

## Основная формула

1. Категории ПДн получают базовый вклад из `risk.category_weights`.
2. Повторные находки добавляют ограниченный вклад через:
   - `category_repeat_factor`;
   - `category_repeat_cap`;
   - `category_max_multiplier`.
3. Далее применяются `rule_scores`: boost и suppress правила.
4. Если ПДн не найдено, score ограничивается `no_pii_score_cap`, кроме специальных unread/OCR/video случаев.
5. Файл попадает в submit, если `score >= default_submit_threshold` или CLI `--risk-threshold`.

## Что обычно повышает score

- паспорт, СНИЛС, ИНН физлица, MRZ, CVV, банковские карты;
- сочетание ФИО с сильным идентификатором;
- ФИО + контакты/адрес в неформальном контексте;
- массовая таблица с чувствительными колонками;
- embedded image payload, похожий на документ;
- employee/private папки вроде `Мои бумажки`;
- путь с `выгруз`, `dump`, `backup`, `passport`, `анкета`, `заявка`.

## Что обычно снижает score

- публичный или деловой контекст: policy, agreement, regulation, устав, отчет, закон;
- бизнес-реквизиты юрлица без профиля физлица;
- логистические/операционные таблицы без сильных идентификаторов;
- web/site dumps без сильного профиля;
- слабые одиночные card-like совпадения без карточного контекста.

## Настраиваемые параметры

Все переносимые веса находятся в `detector_settings.json`.

| Раздел | Примеры |
|---|---|
| `risk.default_submit_threshold` | Основной порог submit. |
| `risk.category_weights` | Вес категорий `passport_rf`, `bank_card`, `fio`. |
| `risk.rule_scores` | Веса `person_profile_combo`, `public_structured_noise`, etc. |
| `risk.suspicious_path_score` | Base/per-keyword/cap для подозрительного пути. |
| `risk.benign_path_keywords` | Слова для делового/public suppress. |
| `risk.billing_full_dump_contexts` | Контексты, где full billing dump не подавляется как логистика. |

Подробная карта параметров: [settings guide](settings.md).

## Как читать отчеты

В `risk_report_*.md` важны:

- `score` - насколько уверенно файл выше/ниже submit;
- `categories` - какие ПДн нашли detector-ы;
- `rules` - почему score изменился.

В `review_report_*.md` смотрите:

- `Submit` - что ушло в `.txt`;
- `Review Candidates` - что близко к порогу;
- `Top Suppressed` - где были признаки, но suppress-правила победили.

## Добавление нового правила

1. Добавьте вес в `detector_settings.json -> risk.rule_scores`.
2. В коде используйте `_rule_score("new_rule", default)`.
3. Добавьте `RiskRuleHit`.
4. Проверьте, что правило видно в reports.

Пример:

```python
if condition:
    delta = _rule_score("new_rule", 25)
    score += delta
    hits.append(RiskRuleHit("new_rule", delta, "Почему файл стал рискованнее."))
```

Не кодируйте конкретные пути из датасета. Формулируйте правило как общий переносимый сигнал.
