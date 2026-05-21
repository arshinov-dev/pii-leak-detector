from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List

from extraction_planner import ExtractionPlan, ExtractionStep
from text_blocks import TextBlock
import text_extractors as tx


ExtractorFn = Callable[[str, Dict[str, Any]], List[TextBlock]]


EXTRACTOR_REGISTRY: Dict[str, ExtractorFn] = {
    "plain_text_extractor": tx.extract_plain_text,
    "html_text_extractor": tx.extract_html_text,
    "csv_extractor": tx.extract_csv_text,
    "json_extractor": tx.extract_json_text,
    "parquet_extractor": tx.extract_parquet_text,
    "spreadsheet_extractor": tx.extract_spreadsheet_text,
    "pdf_text_extractor": tx.extract_pdf_text,
    "docx_text_extractor": tx.extract_docx_text,
    "rtf_text_extractor": tx.extract_rtf_text,
    "binary_embedded_payload_extractor": tx.extract_binary_embedded_payload_text,
    "image_ocr_extractor": tx.extract_ocr_text,
    "pdf_page_ocr_extractor": tx.extract_ocr_text,
    "video_frame_ocr_extractor": tx.extract_ocr_text,
}


UNSUPPORTED_PRIMARY_EXTRACTORS = {
    "legacy_doc_extractor": "Legacy DOC requires a converter or a dedicated reader; it is not part of the basic text extractor layer.",
    "legacy_office_extractor": "Legacy OLE Office probing requires a converter or a dedicated reader; it is not part of the basic text extractor layer.",
    "presentation_text_extractor": "Presentation extraction is deferred to a later module.",
    "archive_inventory": "Archive inventory requires a separate safe unpacking policy.",
    "document_text_extractor": "Generic document fallback is not implemented in the basic extractor layer.",
    "structured_extractor": "Generic structured fallback is not implemented; use a concrete extractor.",
    "image_prefilter": "Image prefilter is not a text extractor and will be handled before OCR integration.",
    "video_metadata_extractor": "Video metadata extraction is deferred to the OCR/video integration stage.",
}


@dataclass
class ExtractionRunResult:
    """
    Result of executing extraction steps for a single plan.
    """

    path: str
    strategy: str
    blocks: List[TextBlock] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    skipped_steps: List[str] = field(default_factory=list)
    failed_steps: List[str] = field(default_factory=list)
    skipped_file: bool = False

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def char_count(self) -> int:
        return sum(block.char_count for block in self.blocks)

    @property
    def has_text(self) -> bool:
        return any(block.has_text for block in self.blocks)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["blocks"] = [block.to_dict() for block in self.blocks]
        data["block_count"] = self.block_count
        data["char_count"] = self.char_count
        data["has_text"] = self.has_text
        return data


def run_extraction_plans(
    plans: Iterable[ExtractionPlan],
    include_escalations: bool = False,
) -> Iterator[ExtractionRunResult]:
    for plan in plans:
        yield run_extraction_plan(plan, include_escalations=include_escalations)


def run_extraction_plan(
    plan: ExtractionPlan,
    include_escalations: bool = False,
) -> ExtractionRunResult:
    result = ExtractionRunResult(path=plan.path, strategy=plan.strategy)

    if plan.skip_reason:
        result.skipped_file = True
        result.warnings.extend(plan.warnings)
        return result

    steps = list(plan.primary_steps)
    if include_escalations:
        steps.extend(plan.escalation_steps)

    for step in sorted(steps, key=lambda item: item.priority):
        _run_step(plan, step, result)

    return result


def summarize_extraction_results(results: Iterable[ExtractionRunResult]) -> Dict[str, Any]:
    result_list = list(results)
    strategy_counter = Counter(result.strategy for result in result_list)
    extractor_counter = Counter(
        block.extraction_method for result in result_list for block in result.blocks
    )
    skipped_step_counter = Counter(
        step_name for result in result_list for step_name in result.skipped_steps
    )
    failed_step_counter = Counter(
        step_name for result in result_list for step_name in result.failed_steps
    )
    warning_count = sum(len(result.warnings) for result in result_list) + sum(
        len(block.warnings) for result in result_list for block in result.blocks
    )
    failed_examples = [
        {
            "path": result.path,
            "steps": list(result.failed_steps),
            "warning": _first_warning(result),
        }
        for result in result_list
        if result.failed_steps
    ][:10]

    return {
        "total_files": len(result_list),
        "skipped_files": sum(1 for result in result_list if result.skipped_file),
        "files_with_text": sum(1 for result in result_list if result.has_text),
        "total_blocks": sum(result.block_count for result in result_list),
        "text_blocks": sum(
            1 for result in result_list for block in result.blocks if block.has_text
        ),
        "total_chars": sum(result.char_count for result in result_list),
        "warnings": warning_count,
        "strategies": dict(strategy_counter.most_common()),
        "extractors": dict(extractor_counter.most_common()),
        "skipped_steps": dict(skipped_step_counter.most_common()),
        "failed_steps": dict(failed_step_counter.most_common()),
        "failed_examples": failed_examples,
    }


def print_extraction_report(results: Iterable[ExtractionRunResult]) -> None:
    summary = summarize_extraction_results(results)

    print("\n" + "=" * 60)
    print("ИЗВЛЕЧЕНИЕ ТЕКСТА")
    print("=" * 60)
    print(f"Файлов обработано:   {summary['total_files']}")
    print(f"Файлов пропущено:    {summary['skipped_files']}")
    print(f"Файлов с текстом:    {summary['files_with_text']}")
    print(f"Блоков всего:        {summary['total_blocks']}")
    print(f"Блоков с текстом:    {summary['text_blocks']}")
    print(f"Символов текста:     {summary['total_chars']}")
    print(f"Предупреждений:      {summary['warnings']}")

    _print_counter("Извлекатели", summary["extractors"])
    _print_counter("Пропущенные шаги", summary["skipped_steps"])
    _print_counter("Ошибки шагов", summary["failed_steps"])
    _print_failed_examples(summary["failed_examples"])


def _run_step(plan: ExtractionPlan, step: ExtractionStep, result: ExtractionRunResult) -> None:
    if "ocr" in step.extractor and not _should_run_ocr_step(plan, step, result):
        result.skipped_steps.append(step.extractor)
        result.warnings.append(f"{step.extractor}: OCR escalation skipped by targeting rules.")
        return

    extractor = EXTRACTOR_REGISTRY.get(step.extractor)
    if extractor is None:
        reason = UNSUPPORTED_PRIMARY_EXTRACTORS.get(step.extractor, "No extractor registered for this step.")
        result.skipped_steps.append(step.extractor)
        result.blocks.extend(
            tx.extract_unsupported(
                file_path=plan.path,
                extractor_name=step.extractor,
                reason=reason,
                source_type=step.source,
            )
        )
        return

    try:
        params = dict(step.params)
        if "ocr" in step.extractor:
            params.update({"extractor_name": step.extractor, "source_type": step.source})
        result.blocks.extend(extractor(plan.path, params))
    except Exception as exc:
        result.failed_steps.append(step.extractor)
        result.blocks.extend(
            tx.extract_unsupported(
                file_path=plan.path,
                extractor_name=step.extractor,
                reason=f"Extractor failed: {type(exc).__name__}: {exc}",
                source_type=step.source,
            )
        )


def _should_run_ocr_step(plan: ExtractionPlan, step: ExtractionStep, result: ExtractionRunResult) -> bool:
    folded_path = plan.path.casefold()
    suspicious_name = bool(plan.metadata.get("suspicious_name"))
    high_ocr_context = bool(plan.metadata.get("high_ocr_context"))

    if step.extractor == "image_ocr_extractor":
        return plan.extension in {"tif", "tiff"} or suspicious_name or "/архив сканы/" in folded_path

    if step.extractor == "pdf_page_ocr_extractor":
        has_empty_page = any(
            "цифрового текста" in warning.casefold()
            for block in result.blocks
            for warning in block.warnings
        )
        return (not result.has_text or has_empty_page) and (suspicious_name or high_ocr_context or not result.has_text)

    if step.extractor == "video_frame_ocr_extractor":
        return suspicious_name or high_ocr_context or plan.extension == "mp4"

    return suspicious_name or high_ocr_context or not result.has_text


def _print_counter(title: str, counter: Dict[str, int]) -> None:
    if not counter:
        return

    print("-" * 60)
    print(title)
    for key, value in counter.items():
        print(f"{key:<42} | {value}")


def _first_warning(result: ExtractionRunResult) -> str:
    if result.warnings:
        return result.warnings[0]
    for block in result.blocks:
        if block.warnings:
            return block.warnings[0]
    return ""


def _print_failed_examples(examples: List[Dict[str, Any]]) -> None:
    if not examples:
        return

    print("-" * 60)
    print("Примеры ошибок")
    for item in examples:
        steps = ", ".join(item["steps"])
        print(f"{item['path']} -> {steps}: {item['warning']}")
