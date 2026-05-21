from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


LOW_CONFIDENCE_THRESHOLD = 0.5
EMPTY_FILE_BYTES = 0
TINY_FILE_BYTES = 128
SMALL_IMAGE_BYTES = 2 * 1024

PDF_OCR_MAX_PAGES = 12
DOCX_OCR_MAX_IMAGES = 20
PRESENTATION_OCR_MAX_IMAGES = 30
VIDEO_MAX_FRAMES = 30


HIGH_OCR_DIR_KEYWORDS = (
    "архив сканы",
    "выгрузки",
    "scan",
    "scans",
    "dump",
    "backup",
)

SUSPICIOUS_NAME_KEYWORDS = (
    "паспорт",
    "passport",
    "скан",
    "scan",
    "копия",
    "copy",
    "удостовер",
    "driver",
    "license",
    "карта",
    "card",
    "анкета",
    "заявление",
    "согласие",
    "список",
    "выгруз",
    "dump",
    "backup",
    "скрин",
    "screenshot",
    "photo",
    "фото",
)

BUSINESS_CONTEXT_KEYWORDS = (
    "договор",
    "счет",
    "счёт",
    "акт",
    "наклад",
    "приказ",
    "распоряж",
    "agreement",
    "contract",
    "invoice",
    "policy",
    "privacy",
    "terms",
    "regulation",
    "rules",
)


@dataclass
class ExtractionStep:
    """
    One planned extraction operation.

    The planner describes intended work only; concrete extractors decide how to
    execute the step and how to report failures.
    """

    stage: str
    extractor: str
    source: str
    reason: str
    priority: int = 50
    optional: bool = False
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtractionPlan:
    """
    Routing decision for a single file discovered by file_search.py.
    """

    path: str
    name: str
    extension: Optional[str]
    family: Optional[str]
    status: str
    confidence: float
    strategy: str
    primary_steps: List[ExtractionStep] = field(default_factory=list)
    escalation_steps: List[ExtractionStep] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    skip_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def requires_ocr(self) -> bool:
        return any("ocr" in step.extractor for step in self.all_steps)

    @property
    def all_steps(self) -> List[ExtractionStep]:
        return self.primary_steps + self.escalation_steps

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["requires_ocr"] = self.requires_ocr
        return data


def plan_extractions(scan_results: Iterable[Dict[str, Any]]) -> Iterator[ExtractionPlan]:
    """
    Lazily build extraction plans for file_search.py results.
    """

    for scan_result in scan_results:
        yield build_extraction_plan(scan_result)


def build_extraction_plan(scan_result: Dict[str, Any]) -> ExtractionPlan:
    """
    Decide how a scanned file should be processed by downstream extractors.

    The function deliberately avoids reading file content. It uses only scanner
    metadata: family, extension, MIME, status, confidence, path, name and size.
    """

    path = str(scan_result.get("path") or "")
    name = str(scan_result.get("decoded_name") or scan_result.get("name") or Path(path).name)
    extension = _lower_or_none(scan_result.get("extension"))
    family = _lower_or_none(scan_result.get("family"))
    status = str(scan_result.get("status") or "unknown")
    confidence = _float_or_zero(scan_result.get("confidence"))
    size_bytes = int(scan_result.get("size_bytes") or 0)

    metadata = {
        "size_bytes": size_bytes,
        "mime": scan_result.get("mime"),
        "original_extension": scan_result.get("original_extension"),
        "scanner_method": scan_result.get("method"),
        "scanner_message": scan_result.get("message"),
        "suspicious_name": _has_keyword(path, SUSPICIOUS_NAME_KEYWORDS),
        "business_context_name": _has_keyword(path, BUSINESS_CONTEXT_KEYWORDS),
        "high_ocr_context": _has_keyword(path, HIGH_OCR_DIR_KEYWORDS),
    }

    plan = ExtractionPlan(
        path=path,
        name=name,
        extension=extension,
        family=family,
        status=status,
        confidence=confidence,
        strategy="pending",
        metadata=metadata,
    )

    if status == "error":
        return _skip(plan, "scanner_error", "Сканер сообщил об ошибке чтения файла.")

    if size_bytes == EMPTY_FILE_BYTES:
        return _skip(plan, "empty_file", "Файл пустой, извлекать нечего.")

    if size_bytes <= TINY_FILE_BYTES:
        plan.warnings.append("Файл очень маленький; извлечение может быть нерезультативным.")

    if confidence < LOW_CONFIDENCE_THRESHOLD:
        plan.warnings.append("Низкая уверенность определения формата.")

    if family == "executable":
        return _skip(plan, "executable", "Исполняемые файлы исключаются из ПДн-пайплайна.")

    if family == "archive":
        plan.strategy = "defer_archive"
        plan.warnings.append("Архивы требуют отдельной безопасной политики распаковки.")
        plan.primary_steps.append(
            ExtractionStep(
                stage="primary",
                extractor="archive_inventory",
                source="archive",
                reason="Сначала нужно построить список содержимого архива без извлечения файлов наружу.",
                priority=70,
                optional=True,
                params={"max_members": 5000},
            )
        )
        return plan

    if family == "structured":
        return _plan_structured(plan)

    if family == "web":
        return _with_primary(
            plan,
            strategy="cheap_text",
            extractor="html_text_extractor",
            source="html",
            reason="HTML читается без OCR через парсинг и очистку текстового содержимого.",
            priority=10,
            params={"preserve_links": False, "strip_scripts": True},
        )

    if family == "text":
        return _with_primary(
            plan,
            strategy="cheap_text",
            extractor="plain_text_extractor",
            source="file",
            reason="Текстовый формат можно читать напрямую с подбором кодировки.",
            priority=10,
            params={"encodings": ["utf-8-sig", "utf-8", "cp1251"]},
        )

    if family == "spreadsheet":
        return _with_primary(
            plan,
            strategy="table_parse",
            extractor="spreadsheet_extractor",
            source="workbook",
            reason="Табличный файл нужно разбирать структурно по листам и ячейкам.",
            priority=15,
            params={"stream_rows": True, "include_sheet_names": True},
        )

    if family == "document":
        return _plan_document(plan)

    if family == "presentation":
        return _plan_presentation(plan)

    if family == "image":
        return _plan_image(plan)

    if family == "video":
        return _plan_video(plan)

    if not scan_result.get("is_binary"):
        return _with_primary(
            plan,
            strategy="cautious_text_fallback",
            extractor="plain_text_extractor",
            source="file",
            reason="Формат не распознан, но файл выглядит текстовым.",
            priority=60,
            params={"encodings": ["utf-8-sig", "utf-8", "cp1251"]},
        )

    plan.strategy = "manual_review_or_custom_extractor"
    plan.warnings.append("Для бинарного файла без распознанного семейства нет безопасного дешевого извлечения.")
    return plan


def summarize_plans(plans: Iterable[ExtractionPlan]) -> Dict[str, Any]:
    """
    Return aggregate counters useful for CLI reports and smoke checks.
    """

    plan_list = list(plans)
    strategy_counter = Counter(plan.strategy for plan in plan_list)
    primary_counter = Counter(step.extractor for plan in plan_list for step in plan.primary_steps)
    escalation_counter = Counter(
        step.extractor for plan in plan_list for step in plan.escalation_steps
    )
    skipped = sum(1 for plan in plan_list if plan.skip_reason)
    ocr_escalation_plans = sum(1 for plan in plan_list if plan.requires_ocr)
    mandatory_ocr_plans = sum(
        1
        for plan in plan_list
        if any("ocr" in step.extractor and not step.optional for step in plan.all_steps)
    )

    return {
        "total": len(plan_list),
        "skipped": skipped,
        "ocr_escalation_plans": ocr_escalation_plans,
        "mandatory_ocr_plans": mandatory_ocr_plans,
        "strategies": dict(strategy_counter.most_common()),
        "primary_extractors": dict(primary_counter.most_common()),
        "escalation_extractors": dict(escalation_counter.most_common()),
    }


def print_plan_report(plans: Iterable[ExtractionPlan]) -> None:
    """
    Print a compact human-readable summary for manual runs.
    """

    summary = summarize_plans(plans)

    print("\n" + "=" * 60)
    print("ПЛАН ИЗВЛЕЧЕНИЯ")
    print("=" * 60)
    print(f"Всего планов:        {summary['total']}")
    print(f"Пропущено:           {summary['skipped']}")
    print(f"OCR может понадоб.:  {summary['ocr_escalation_plans']}")
    print(f"OCR сразу:           {summary['mandatory_ocr_plans']}")

    _print_counter("Стратегии", summary["strategies"])
    _print_counter("Основные извлекатели", summary["primary_extractors"])
    _print_counter("OCR/эскалации", summary["escalation_extractors"])


def _plan_structured(plan: ExtractionPlan) -> ExtractionPlan:
    extension = plan.extension or "structured"
    extractor = {
        "csv": "csv_extractor",
        "tsv": "csv_extractor",
        "json": "json_extractor",
        "parquet": "parquet_extractor",
    }.get(extension, "structured_extractor")

    params: Dict[str, Any] = {"format": extension, "stream_rows": True}
    if extension in {"csv", "tsv"}:
        params["delimiter"] = "\t" if extension == "tsv" else "auto"

    return _with_primary(
        plan,
        strategy="structured_parse",
        extractor=extractor,
        source="table",
        reason="Структурированные данные нужно читать парсером, сохраняя строки и колонки.",
        priority=10,
        params=params,
    )


def _plan_document(plan: ExtractionPlan) -> ExtractionPlan:
    extension = plan.extension

    if plan.metadata.get("mime") == "application/vnd.ms-office":
        plan.strategy = "legacy_office_container"
        plan.primary_steps.append(
            ExtractionStep(
                stage="primary",
                extractor="legacy_office_extractor",
                source="document",
                reason="Файл является OLE-контейнером Office, даже если расширение выглядит иначе.",
                priority=40,
                params={"declared_extension": extension, "fallback": "libreoffice_probe"},
            )
        )
        plan.warnings.append("Расширение и бинарный контейнер не совпадают.")
        return plan

    if extension == "pdf":
        plan.strategy = "pdf_text_then_targeted_ocr"
        plan.primary_steps.append(
            ExtractionStep(
                stage="primary",
                extractor="pdf_text_extractor",
                source="pages",
                reason="Сначала извлекается цифровой текст PDF по страницам.",
                priority=10,
                params={"include_page_stats": True},
            )
        )
        plan.escalation_steps.append(
            ExtractionStep(
                stage="escalation",
                extractor="pdf_page_ocr_extractor",
                source="pages",
                reason="OCR нужен только для страниц без текстового слоя, с крупными изображениями или с подозрительным именем файла.",
                priority=_ocr_priority(plan),
                optional=True,
                params={
                    "engine": "pymupdf_ocr",
                    "fallback": "render_tesseract",
                    "max_pages": PDF_OCR_MAX_PAGES,
                    "trigger": "empty_or_short_text_or_large_image",
                },
            )
        )
        return plan

    if extension == "docx":
        plan.strategy = "docx_text_then_embedded_ocr"
        plan.primary_steps.append(
            ExtractionStep(
                stage="primary",
                extractor="docx_text_extractor",
                source="document",
                reason="DOCX читается напрямую: параграфы, таблицы, headers и footers.",
                priority=10,
                params={"include_tables": True, "include_headers": True},
            )
        )
        plan.escalation_steps.append(
            ExtractionStep(
                stage="escalation",
                extractor="embedded_image_ocr_extractor",
                source="docx_images",
                reason="OCR нужен только для крупных embedded images или если прямой текст пустой.",
                priority=_ocr_priority(plan),
                optional=True,
                params={"max_images": DOCX_OCR_MAX_IMAGES, "min_width_px": 400, "min_height_px": 250},
            )
        )
        return plan

    if extension == "rtf":
        return _with_primary(
            plan,
            strategy="cheap_text",
            extractor="rtf_text_extractor",
            source="document",
            reason="RTF можно обработать как текстовый документ с очисткой управляющих конструкций.",
            priority=20,
            params={"strip_rtf_control_words": True},
        )

    if extension == "doc":
        return _with_primary(
            plan,
            strategy="office_conversion",
            extractor="legacy_doc_extractor",
            source="document",
            reason="Старый DOC требует специализированного чтения или конвертации через LibreOffice.",
            priority=35,
            params={"fallback": "libreoffice_to_docx_or_pdf"},
        )

    plan.strategy = "generic_document"
    plan.primary_steps.append(
        ExtractionStep(
            stage="primary",
            extractor="document_text_extractor",
            source="document",
            reason="Документ распознан не полностью; нужен общий обработчик документов.",
            priority=50,
            params={"format": extension},
        )
    )
    plan.warnings.append("Неизвестный подтип документа.")
    return plan


def _plan_presentation(plan: ExtractionPlan) -> ExtractionPlan:
    plan.strategy = "presentation_text_then_embedded_ocr"
    plan.primary_steps.append(
        ExtractionStep(
            stage="primary",
            extractor="presentation_text_extractor",
            source="slides",
            reason="Текст презентации извлекается напрямую по слайдам и таблицам.",
            priority=25,
            params={"include_tables": True, "fallback": "libreoffice_to_pdf"},
        )
    )
    plan.escalation_steps.append(
        ExtractionStep(
            stage="escalation",
            extractor="embedded_image_ocr_extractor",
            source="slide_images",
            reason="Изображения на слайдах OCR-ятся только при крупном размере или пустом текстовом слое.",
            priority=_ocr_priority(plan),
            optional=True,
            params={"max_images": PRESENTATION_OCR_MAX_IMAGES, "min_width_px": 400, "min_height_px": 250},
        )
    )
    return plan


def _plan_image(plan: ExtractionPlan) -> ExtractionPlan:
    if (plan.metadata.get("size_bytes") or 0) < SMALL_IMAGE_BYTES and not plan.metadata["suspicious_name"]:
        return _skip(plan, "tiny_image", "Изображение слишком маленькое для полезного OCR.")

    plan.strategy = "image_prefilter_then_ocr"
    plan.primary_steps.append(
        ExtractionStep(
            stage="primary",
            extractor="image_prefilter",
            source="image",
            reason="Перед OCR нужно отсеять логотипы, иконки, пустые изображения и шум.",
            priority=15,
            params={
                "min_width_px": 300,
                "min_height_px": 200,
                "check_document_like_layout": True,
                "check_text_regions": True,
            },
        )
    )
    plan.escalation_steps.append(
        ExtractionStep(
            stage="escalation",
            extractor="image_ocr_extractor",
            source="image",
            reason="OCR запускается, если prefilter подтвердил документ, скан, скриншот или подозрительный контекст.",
            priority=_ocr_priority(plan),
            optional=True,
            params={"languages": "rus+eng", "try_document_crop": True},
        )
    )
    return plan


def _plan_video(plan: ExtractionPlan) -> ExtractionPlan:
    plan.strategy = "video_sparse_frame_ocr"
    plan.primary_steps.append(
        ExtractionStep(
            stage="primary",
            extractor="video_metadata_extractor",
            source="video",
            reason="Сначала нужно получить длительность и параметры видео для лимитов OCR.",
            priority=40,
            params={"include_duration": True, "include_resolution": True},
        )
    )
    plan.escalation_steps.append(
        ExtractionStep(
            stage="escalation",
            extractor="video_frame_ocr_extractor",
            source="sampled_frames",
            reason="Видео обрабатывается только редкими кадрами с жестким лимитом.",
            priority=_ocr_priority(plan),
            optional=True,
            params={"max_frames": VIDEO_MAX_FRAMES, "sample_interval_sec": 1.0},
        )
    )
    return plan


def _with_primary(
    plan: ExtractionPlan,
    strategy: str,
    extractor: str,
    source: str,
    reason: str,
    priority: int,
    params: Optional[Dict[str, Any]] = None,
) -> ExtractionPlan:
    plan.strategy = strategy
    plan.primary_steps.append(
        ExtractionStep(
            stage="primary",
            extractor=extractor,
            source=source,
            reason=reason,
            priority=priority,
            params=params or {},
        )
    )
    return plan


def _skip(plan: ExtractionPlan, reason_code: str, reason: str) -> ExtractionPlan:
    plan.strategy = "skip"
    plan.skip_reason = reason_code
    plan.warnings.append(reason)
    return plan


def _ocr_priority(plan: ExtractionPlan) -> int:
    if plan.extension in {"tif", "tiff"}:
        return 10
    if plan.metadata.get("high_ocr_context") or plan.metadata.get("suspicious_name"):
        return 15
    if plan.metadata.get("business_context_name"):
        return 65
    return 40


def _has_keyword(value: str, keywords: Iterable[str]) -> bool:
    folded = value.casefold()
    return any(keyword.casefold() in folded for keyword in keywords)


def _lower_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).lower()


def _float_or_zero(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _print_counter(title: str, counter: Dict[str, int]) -> None:
    if not counter:
        return

    print("-" * 60)
    print(title)
    for key, value in counter.items():
        print(f"{key:<42} | {value}")
