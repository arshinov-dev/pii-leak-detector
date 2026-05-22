import argparse
from collections import Counter
from pathlib import Path

import extraction_planner as ep
import extraction_runner as er
import file_search as fs
import pii_detector as pii
import risk_classifier as risk


FAST_SUBMIT_DEFAULT = "out/submit_fast.txt"
FAST_RISK_REPORT_DEFAULT = "out/risk_report_fast.md"
FAST_PIPELINE_REPORT_DEFAULT = "out/pipeline_report_fast.md"

FAST_EXPLICIT_NAME_KEYWORDS = (
    "паспорт",
    "passport",
    "удостовер",
    "identity",
    "identification",
    "driver",
    "license",
    "анкета",
    "заявление",
    "согласие",
    "пропуск",
    "дмс",
    "dms",
    "personal",
    "личн",
    "scan",
    "скан",
    "photo",
    "фото",
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII leak detector pipeline")
    parser.add_argument("folder", nargs="?", default="share", help="Папка для сканирования.")
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Только инвентаризация файлов без извлечения, риск-оценки и submit.",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="После инвентаризации построить и вывести сводку планов извлечения.",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Выполнить базовое извлечение текста по primary-шагам планов без OCR.",
    )
    parser.add_argument(
        "--extract-limit",
        type=int,
        default=None,
        help="Ограничить количество планов для smoke-прогона извлечения.",
    )
    parser.add_argument(
        "--ocr",
        action="store_true",
        help="Запускать целевые OCR-эскалации для сканов, изображений, PDF без текста и видео.",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Быстрый submit-режим: не разбирать массовые PDF/HTML/images, но проверить текст, таблицы, видео и ELF embedded payload.",
    )
    parser.add_argument(
        "--detect-pii",
        action="store_true",
        help="После базового извлечения текста найти категории ПДн.",
    )
    parser.add_argument(
        "--risk",
        action="store_true",
        help="Оценить риск и вывести сводку файлов-кандидатов для submit.",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=risk.DEFAULT_SUBMIT_THRESHOLD,
        help="Порог score для включения файла в submit.",
    )
    parser.add_argument(
        "--submit",
        default=None,
        help="Записать .txt submit со списком подозрительных файлов.",
    )
    parser.add_argument(
        "--risk-report",
        default=None,
        help="Записать Markdown-отчет с оценками риска и сработавшими правилами.",
    )
    parser.add_argument(
        "--pipeline-report",
        default=None,
        help="Записать Markdown-отчет по этапам pipeline и fast-selection.",
    )
    return parser.parse_args()


def _has_action(args: argparse.Namespace) -> bool:
    return any(
        (
            args.scan_only,
            args.plan,
            args.extract,
            args.detect_pii,
            args.risk,
            args.submit,
            args.risk_report,
            args.pipeline_report,
            args.fast,
        )
    )


def _configure_default_mode(args: argparse.Namespace) -> None:
    output_only = (
        (args.submit or args.risk_report or args.pipeline_report)
        and not any((args.scan_only, args.plan, args.extract, args.detect_pii, args.risk, args.ocr, args.fast))
    )

    if not _has_action(args) or output_only:
        args.fast = True

    if args.fast:
        args.risk = True
        if not args.submit:
            args.submit = FAST_SUBMIT_DEFAULT
        if not args.risk_report:
            args.risk_report = FAST_RISK_REPORT_DEFAULT
        if not args.pipeline_report:
            args.pipeline_report = FAST_PIPELINE_REPORT_DEFAULT


def _fast_candidate_selection(plans):
    selected = []
    decisions = []
    for plan in plans:
        include, reason = _fast_selection_reason(plan)
        decisions.append({"plan": plan, "include": include, "reason": reason})
        if include:
            selected.append(plan)
    return selected, decisions


def _fast_selection_reason(plan):
    family = plan.family or "unknown"
    extension = plan.extension or "unknown"
    folded_path = plan.path.casefold()
    folded_name = plan.name.casefold()
    explicit_name_signal = _has_explicit_fast_keyword(folded_name)
    employee_context = "мои бумажки" in folded_path or "employes" in folded_path or "employees" in folded_path

    if family == "executable":
        return True, "include: executable binary payload probe"
    if family == "video":
        return True, "include: video manual review candidate"
    if family in {"text", "structured", "spreadsheet"}:
        return True, "include: cheap text/table parser"
    if family == "document" and extension in {"docx", "rtf", "doc"} and (explicit_name_signal or employee_context):
        return True, "include: office document with explicit/employee context"
    if family == "web" and explicit_name_signal:
        return True, "include: web page with explicit file-name signal"

    if family == "document" and extension == "pdf":
        return False, "skip: PDF is expensive in fast mode"
    if family in {"image", "presentation"}:
        return False, "skip: OCR-heavy media in fast mode"
    if family == "web":
        return False, "skip: mass web snapshot without explicit file-name signal"
    if family == "document":
        return False, "skip: document without fast-mode context"
    return False, "skip: no fast-mode rule"


def _has_explicit_fast_keyword(folded_name: str) -> bool:
    return any(keyword.casefold() in folded_name for keyword in FAST_EXPLICIT_NAME_KEYWORDS)


def _write_pipeline_report(
    output_path: str,
    scan_results,
    plans,
    extraction_plans,
    fast_decisions,
    extraction_results,
    pii_results,
    assessments,
    threshold: float,
    submit_lines,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    scan_counter = Counter(_scan_type_key(item) for item in scan_results)
    selected_reason_counter = Counter(item["reason"] for item in fast_decisions if item["include"])
    skipped_reason_counter = Counter(item["reason"] for item in fast_decisions if not item["include"])
    selected_type_counter = Counter((item["plan"].family or "unknown", item["plan"].extension or "unknown") for item in fast_decisions if item["include"])
    skipped_type_counter = Counter((item["plan"].family or "unknown", item["plan"].extension or "unknown") for item in fast_decisions if not item["include"])

    lines = [
        "# Pipeline report",
        "",
        "## Mode",
        "",
        "Fast mode runs cheap extraction and binary payload probing. Mass PDF, web snapshots, images, and presentations are skipped unless they have an explicit file-name signal.",
        "",
        "## Outputs",
        "",
        f"- Submit paths: `{len(submit_lines)}`",
        f"- Risk threshold: `{threshold}`",
        "",
        "## Scan",
        "",
        f"- Total files: `{len(scan_results)}`",
        f"- Planned files: `{len(plans)}`",
        f"- Extracted candidates: `{len(extraction_plans)}`",
        "",
        "| type | count |",
        "|---|---:|",
    ]

    for item, count in scan_counter.most_common():
        lines.append(f"| {item} | {count} |")

    lines.extend(["", "## Fast Selection", ""])
    lines.extend(_counter_table("Selected reasons", selected_reason_counter))
    lines.extend([""])
    lines.extend(_counter_table("Skipped reasons", skipped_reason_counter))
    lines.extend([""])
    lines.extend(_counter_table("Selected type/family", selected_type_counter))
    lines.extend([""])
    lines.extend(_counter_table("Skipped type/family", skipped_type_counter, limit=25))

    lines.extend(["", "## Selected Candidates", "", "| path | reason |", "|---|---|"])
    for item in fast_decisions:
        if item["include"]:
            lines.append(f"| `{item['plan'].path}` | {item['reason']} |")

    lines.extend(["", "## Risk Top", "", "| score | submit | type | categories | rules |", "|---:|---|---|---|---|"])
    for assessment in sorted(assessments, key=lambda item: item.score, reverse=True)[:100]:
        categories = ", ".join(f"{key}:{value}" for key, value in list(assessment.categories.items())[:6])
        rules = "; ".join(f"{hit.rule}({hit.score_delta:+.0f})" for hit in assessment.rule_hits[:6])
        lines.append(f"| {assessment.score:.1f} | `{assessment.submit_path}` | {assessment.document_type} | {categories} | {rules} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _counter_table(title: str, counter: Counter, limit: int = 50):
    lines = [f"### {title}", "", "| item | count |", "|---|---:|"]
    for item, count in counter.most_common(limit):
        lines.append(f"| `{item}` | {count} |")
    if not counter:
        lines.append("| none | 0 |")
    return lines


def _scan_type_key(scan_result):
    extension = (scan_result.get("extension") or "unknown").upper()
    mime = scan_result.get("mime") or "unknown"
    return f"{extension} ({mime})"


if __name__ == "__main__":
    args = _parse_args()
    _configure_default_mode(args)

    try:
        share_root = fs.resolve_scan_root(args.folder)
        files_stream = fs.traverse_data_folder(str(share_root))
        scan_results = fs.count_and_report_files(files_stream)
        if args.scan_only:
            raise SystemExit(0)
        needs_risk = bool(args.risk or args.submit or args.risk_report or args.pipeline_report)
        if args.plan or args.extract or args.detect_pii or needs_risk:
            plans = list(ep.plan_extractions(scan_results))
        fast_decisions = []
        if args.plan:
            ep.print_plan_report(plans)
        if args.extract or args.detect_pii or needs_risk:
            extraction_plans = plans[: args.extract_limit] if args.extract_limit else plans
            if args.fast:
                extraction_plans, fast_decisions = _fast_candidate_selection(extraction_plans)
                print(f"\nFAST mode: обработка {len(extraction_plans)} кандидатов вместо {len(plans)} файлов.")
            results = list(er.run_extraction_plans(extraction_plans, include_escalations=args.ocr))
        if args.extract:
            er.print_extraction_report(results)
        if args.detect_pii or needs_risk:
            pii_results = pii.scan_extraction_results(results)
        if args.detect_pii:
            pii.print_pii_report(pii_results)
        if needs_risk:
            assessments = risk.assess_risks(pii_results, extraction_plans, results, str(share_root))
        if args.risk:
            risk.print_risk_report(assessments, threshold=args.risk_threshold)
        if args.submit:
            lines = risk.write_submit_file(assessments, args.submit, threshold=args.risk_threshold)
            print(f"\nSubmit записан: {args.submit} ({len(lines)} файлов)")
        else:
            lines = []
        if args.risk_report:
            risk.write_risk_report(assessments, args.risk_report, threshold=args.risk_threshold)
            print(f"Risk report записан: {args.risk_report}")
        if args.pipeline_report:
            _write_pipeline_report(
                output_path=args.pipeline_report,
                scan_results=scan_results,
                plans=plans,
                extraction_plans=extraction_plans,
                fast_decisions=fast_decisions,
                extraction_results=results,
                pii_results=pii_results,
                assessments=assessments,
                threshold=args.risk_threshold,
                submit_lines=lines,
            )
            print(f"Pipeline report записан: {args.pipeline_report}")
    except FileNotFoundError as exc:
        print(exc)
        raise SystemExit(1)
