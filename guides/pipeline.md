# Полный цикл PII Leak Detector

## End-to-end схема

```mermaid
flowchart TD
    A["share/ directory"] --> B["file_search.py<br/>инвентаризация файлов"]
    B --> C["FileScanResult<br/>format, MIME, family, confidence"]
    C --> D["extraction_planner.py<br/>маршрут обработки"]
    D --> E["ExtractionPlan<br/>primary steps + OCR escalations"]
    E --> F["extraction_runner.py<br/>исполнение primary-шагов"]
    F --> G["text_extractors.py<br/>cheap text/table extraction"]
    G --> H["TextBlock<br/>page/sheet/row provenance"]
    H --> I["pii_detector.py<br/>категории ПДн + валидаторы"]
    I --> J["PiiFileResult<br/>counts, categories, masked examples"]
    J --> K["risk_classifier.py<br/>recall-friendly scoring"]
    E --> K
    F --> K
    K --> L["RiskAssessment<br/>score, level, rule hits"]
    L --> M["submit.txt<br/>пути от корня share"]
    L --> N["risk_report.md<br/>debug report"]

    E -. "OCR escalation planned,<br/>not executed in basic pipeline" .-> O["future OCR layer<br/>targeted image/PDF/video OCR"]
    O -. "future TextBlock" .-> H
```

## Что делает каждый слой

| Слой | Вход | Выход | Ответственность |
|---|---|---|---|
| `file_search.py` | Путь к папке | `FileScanResult` | Быстро определить формат, MIME, family, размер и уверенность. |
| `extraction_planner.py` | `FileScanResult` | `ExtractionPlan` | Решить, какой extractor нужен и где может понадобиться OCR. |
| `extraction_runner.py` | `ExtractionPlan` | `ExtractionRunResult` | Запустить primary-шаги и собрать блоки текста. |
| `text_extractors.py` | Файл + параметры шага | `TextBlock` | Дешево извлечь цифровой текст, таблицы и HTML без OCR. |
| `pii_detector.py` | `TextBlock` | `PiiFileResult` | Найти категории ПДн, валидировать контрольные суммы, маскировать примеры. |
| `risk_classifier.py` | Plan + extraction + PII | `RiskAssessment` | Оценить подозрительность, выбрать submit-кандидатов, объяснить правила. |

## Текущий runtime-путь

```mermaid
sequenceDiagram
    participant CLI as main.py
    participant FS as file_search
    participant Planner as extraction_planner
    participant Runner as extraction_runner
    participant Extractors as text_extractors
    participant PII as pii_detector
    participant Risk as risk_classifier

    CLI->>FS: traverse_data_folder(folder)
    FS-->>CLI: file paths
    CLI->>FS: count_and_report_files(paths)
    FS-->>CLI: scan_results

    CLI->>Planner: plan_extractions(scan_results)
    Planner-->>CLI: ExtractionPlan[]

    CLI->>Runner: run_extraction_plans(plans)
    Runner->>Extractors: run registered primary extractors
    Extractors-->>Runner: TextBlock[]
    Runner-->>CLI: ExtractionRunResult[]

    CLI->>PII: scan_extraction_results(results)
    PII-->>CLI: PiiFileResult[]

    CLI->>Risk: assess_risks(pii, plans, results, share_root)
    Risk-->>CLI: RiskAssessment[]
    CLI->>Risk: write_submit_file(...)
    CLI->>Risk: write_risk_report(...)
```

## Команды

Полный baseline submit:

```bash
python main.py share --risk --submit out/submit.txt --risk-report out/risk_report.md
```

Все сводки сразу:

```bash
python main.py share --plan --extract --detect-pii --risk --submit out/submit.txt --risk-report out/risk_report.md
```

Smoke-прогон:

```bash
python main.py share --risk --extract-limit 180
```

## Важные границы

- OCR сейчас только планируется в `ExtractionPlan`, но не выполняется в базовом pipeline.
- `pii_detector.py` не решает, является ли файл утечкой; он только дает признаки.
- `risk_classifier.py` формирует текущий baseline submit для бота.
- Submit содержит только пути от корня `share`, по одному пути на строку.
