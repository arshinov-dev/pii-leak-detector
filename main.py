import argparse
from collections import Counter
from dataclasses import replace
from pathlib import Path

import extraction_planner as ep
import extraction_runner as er
import file_search as fs
import pii_detector as pii
import risk_classifier as risk
import settings as cfg


MODE_DEFAULTS = cfg.get("mode_defaults", {})
DEFAULT_MAX_OCR_FILES = int(cfg.get("runtime_defaults.max_ocr_files", 80))
DEFAULT_ML_MAX_FILES = int(cfg.get("runtime_defaults.ml_max_files", 40))

TRIAGE_BUCKET_CAPS = cfg.get("triage.bucket_caps", {})
TRIAGE_FAMILY_SCORES = cfg.get("triage.family_scores", {})
TRIAGE_HARD_FAMILY_SCORE_OVERRIDES = cfg.get("triage.hard_family_score_overrides", {})
TRIAGE_EXTENSION_SCORES = cfg.get("triage.extension_scores", {})
TRIAGE_SIGNAL_SCORES = cfg.get("triage.signal_scores", {})
TRIAGE_OCR_CANDIDATE_SCORES = cfg.get("triage.ocr_candidate_scores", {})
TRIAGE_PERSONAL_KEYWORDS = cfg.tuple_setting("triage.personal_keywords")
TRIAGE_EXPORT_KEYWORDS = cfg.tuple_setting("triage.export_keywords")
TRIAGE_LOW_VALUE_EXPORT_NAMES = cfg.tuple_setting("triage.low_value_export_names")
TRIAGE_PUBLIC_CONTEXT_KEYWORDS = cfg.tuple_setting("triage.public_context_keywords")
TRIAGE_OCR_PRIVATE_KEYWORDS = cfg.tuple_setting("triage.ocr_private_keywords")
TRIAGE_OCR_PUBLIC_PENALTY_KEYWORDS = cfg.tuple_setting("triage.ocr_public_penalty_keywords")
FAST_EXPLICIT_NAME_KEYWORDS = cfg.tuple_setting("triage.fast_explicit_name_keywords")


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII leak detector pipeline")
    parser.add_argument("folder", nargs="?", default="share", help="Папка для сканирования.")
    parser.add_argument(
        "--mode",
        choices=sorted(MODE_DEFAULTS),
        default=None,
        help="Режим пайплайна: fast, normal или hard. По умолчанию без флагов запускается fast.",
    )
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
        help="Alias для --mode fast.",
    )
    parser.add_argument(
        "--ml",
        action="store_true",
        help="Включить ML/NER слой. По умолчанию выключен, потому что может быть очень медленным.",
    )
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Отключить ML/NER слой в normal/hard.",
    )
    parser.add_argument(
        "--max-ocr-files",
        type=int,
        default=DEFAULT_MAX_OCR_FILES,
        help="Максимум файлов, которым hard mode разрешит OCR-эскалации.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help="Максимум файлов после triage для normal/hard. По умолчанию: normal=180, hard=520.",
    )
    parser.add_argument(
        "--ml-max-files",
        type=int,
        default=DEFAULT_ML_MAX_FILES,
        help="Максимум файлов, на которых запускается ML/NER при --ml.",
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
    parser.add_argument(
        "--review-report",
        default=None,
        help="Записать Markdown-отчет с кандидатами ниже submit-порога и причинами ручной проверки.",
    )
    return parser.parse_args(argv)


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
            args.review_report,
            args.fast,
            args.mode,
            args.ml,
            args.max_candidates is not None,
        )
    )


def _configure_default_mode(args: argparse.Namespace) -> None:
    output_only = (
        (args.submit or args.risk_report or args.pipeline_report or args.review_report)
        and not any((args.scan_only, args.plan, args.extract, args.detect_pii, args.risk, args.ocr, args.fast))
    )

    if args.fast:
        args.mode = "fast"

    if not _has_action(args) or output_only:
        args.mode = args.mode or "fast"

    if args.mode:
        args.risk = True
        defaults = MODE_DEFAULTS[args.mode]
        if not args.submit:
            args.submit = defaults["submit"]
        if not args.risk_report:
            args.risk_report = defaults["risk_report"]
        if not args.pipeline_report:
            args.pipeline_report = defaults["pipeline_report"]
        if not args.review_report:
            args.review_report = defaults["review_report"]

    if args.no_ml:
        args.ml = False
    elif args.ml:
        args.ml = True
    elif args.mode:
        args.ml = bool(MODE_DEFAULTS[args.mode]["use_ner"])

    if args.mode and args.max_candidates is None:
        args.max_candidates = MODE_DEFAULTS[args.mode]["max_candidates"]


def _mode_candidate_selection(plans, mode: str, max_candidates=None):
    if mode in {"normal", "hard"}:
        return _triage_candidate_selection(
            plans=plans,
            mode=mode,
            max_candidates=max_candidates,
            min_score=float(MODE_DEFAULTS[mode]["triage_min_score"]),
        )

    selected = []
    decisions = []
    for plan in plans:
        include, reason = _selection_reason(plan, mode)
        decisions.append({"plan": plan, "include": include, "reason": reason})
        if include:
            selected.append(plan)
    return selected, decisions


def _triage_candidate_selection(plans, mode: str, max_candidates: int, min_score: float):
    assessments = []
    for plan in plans:
        score, signals, eligible_reason = _triage_score(plan, mode)
        bucket = _triage_bucket(plan)
        assessments.append(
            {
                "plan": plan,
                "score": score,
                "signals": signals,
                "bucket": bucket,
                "eligible_reason": eligible_reason,
            }
        )

    caps = _scaled_bucket_caps(mode, max_candidates)
    bucket_counts: Counter[str] = Counter()
    total_selected = 0
    selected = []
    decisions = []

    for item in sorted(assessments, key=lambda value: (-value["score"], value["plan"].path)):
        plan = item["plan"]
        bucket = item["bucket"]
        score = item["score"]
        signals = item["signals"]
        fast_include, _ = _fast_selection_reason(plan)

        include = False
        if fast_include:
            include = True
            reason = "include: fast baseline"
            selected.append(plan)
            bucket_counts[bucket] += 1
            total_selected += 1
        elif item["eligible_reason"]:
            reason = item["eligible_reason"]
        elif score < min_score:
            reason = "skip: below triage cutoff"
        elif caps.get(bucket, 0) <= 0:
            reason = f"skip: {bucket} disabled in {mode} mode"
        elif bucket_counts[bucket] >= caps.get(bucket, 0):
            reason = f"skip: triage {bucket} bucket cap"
        elif total_selected >= max_candidates:
            reason = "skip: triage total cap"
        else:
            include = True
            reason = f"include: triage {bucket}"
            selected.append(plan)
            bucket_counts[bucket] += 1
            total_selected += 1

        decisions.append(
            {
                "plan": plan,
                "include": include,
                "reason": reason,
                "score": score,
                "signals": signals,
                "bucket": bucket,
            }
        )

    return selected, decisions


def _triage_score(plan, mode: str):
    family = plan.family or "unknown"
    extension = plan.extension or "unknown"
    folded_path = plan.path.casefold()
    folded_name = plan.name.casefold()
    metadata = plan.metadata or {}
    score = 0.0
    signals = []

    if plan.skip_reason:
        return 0.0, [f"planner_skip:{plan.skip_reason}"], f"skip: planner skipped file ({plan.skip_reason})"
    if family == "archive":
        return 0.0, ["archive"], "skip: archive needs separate safe unpacking policy"
    if family in {"image", "presentation"} and mode != "hard":
        return 0.0, [family], f"skip: {family} OCR is reserved for hard mode"

    base_scores = dict(TRIAGE_FAMILY_SCORES)
    if mode == "hard":
        base_scores.update(TRIAGE_HARD_FAMILY_SCORE_OVERRIDES)
    score += _numeric_setting(base_scores, family)
    if family in base_scores:
        signals.append(f"family:{family}")

    if extension in TRIAGE_EXTENSION_SCORES:
        score += _numeric_setting(TRIAGE_EXTENSION_SCORES, extension)
        signals.append(f"ext:{extension}")

    if metadata.get("suspicious_name"):
        score += _triage_signal_score("suspicious_name")
        signals.append("suspicious_name")
    if metadata.get("high_ocr_context"):
        score += _triage_signal_score("high_ocr_context")
        signals.append("high_ocr_context")

    if any(keyword.casefold() in folded_path for keyword in TRIAGE_PERSONAL_KEYWORDS):
        score += _triage_signal_score("personal_keyword")
        signals.append("personal_keyword")
    if any(keyword.casefold() in folded_path for keyword in TRIAGE_EXPORT_KEYWORDS):
        score += _triage_signal_score("export_keyword")
        signals.append("export_keyword")

    if "мои бумажки" in folded_path:
        score += _triage_signal_score("informal_employee_folder")
        signals.append("informal_employee_folder")
    if "employes" in folded_path or "employees" in folded_path:
        score += _triage_signal_score("employee_context")
        signals.append("employee_context")
    if "lost+found" in folded_path and family == "executable":
        score += _triage_signal_score("lost_found_binary")
        signals.append("lost_found_binary")
    if "архив сканы" in folded_path:
        score += _triage_signal_score("scan_archive")
        signals.append("scan_archive")
    if "дочерние предприятия" in folded_path:
        score += _triage_signal_score("subsidiary_context")
        signals.append("subsidiary_context")
    if "billing" in folded_path:
        score += _triage_signal_score("billing_context")
        signals.append("billing_context")
    if "/full/" in folded_path or folded_name.startswith("full"):
        score += _triage_signal_score("full_export")
        signals.append("full_export")
    if "physical" in folded_name or "физ" in folded_path:
        score += _triage_signal_score("physical_person_hint")
        signals.append("physical_person_hint")
    if any(name in folded_name for name in ("customers", "clients", "subscribers")):
        score += _triage_signal_score("people_table_name")
        signals.append("people_table_name")

    if any(name in folded_name for name in TRIAGE_LOW_VALUE_EXPORT_NAMES):
        score += _triage_signal_score("low_value_export_name")
        signals.append("low_value_export_name")
    if "logistic" in folded_path or "логист" in folded_path:
        score += _triage_signal_score("operational_logistics_context")
        signals.append("operational_logistics_context")
    if family == "web" and re_like_page_dump(folded_name):
        score += _triage_signal_score("generic_web_snapshot")
        signals.append("generic_web_snapshot")
    if any(keyword in folded_path for keyword in TRIAGE_PUBLIC_CONTEXT_KEYWORDS):
        score += _triage_signal_score("publicish_context")
        signals.append("publicish_context")
    if metadata.get("business_context_name") and not any(keyword.casefold() in folded_path for keyword in TRIAGE_PERSONAL_KEYWORDS):
        score += _triage_signal_score("business_context")
        signals.append("business_context")

    return max(0.0, score), signals, ""


def _numeric_setting(mapping, key: str, default: float = 0.0) -> float:
    try:
        return float(mapping.get(key, default))
    except (TypeError, ValueError):
        return float(default)


def _triage_signal_score(name: str, default: float = 0.0) -> float:
    return _numeric_setting(TRIAGE_SIGNAL_SCORES, name, default)


def _ocr_candidate_score_value(name: str, default: float = 0.0) -> float:
    return _numeric_setting(TRIAGE_OCR_CANDIDATE_SCORES, name, default)


def re_like_page_dump(folded_name: str) -> bool:
    return folded_name.startswith("page_") and folded_name.endswith((".html", ".htm"))


def _triage_bucket(plan) -> str:
    family = plan.family or "unknown"
    if family in {"text", "structured", "spreadsheet"}:
        return "text_table"
    if family == "document":
        return "document"
    if family == "web":
        return "web"
    if family in {"executable", "video"}:
        return "binary_media"
    if family in {"image", "presentation"}:
        return "ocr_media"
    return "other"


def _scaled_bucket_caps(mode: str, max_candidates: int):
    default_total = int(MODE_DEFAULTS[mode]["max_candidates"])
    caps = TRIAGE_BUCKET_CAPS[mode]
    if max_candidates == default_total:
        return dict(caps)
    scale = max_candidates / max(default_total, 1)
    scaled = {bucket: max(0, int(round(value * scale))) for bucket, value in caps.items()}
    while sum(scaled.values()) < max_candidates:
        bucket = max(caps, key=lambda key: caps[key] - scaled.get(key, 0))
        if caps[bucket] <= 0:
            break
        scaled[bucket] += 1
    return scaled


def _selection_reason(plan, mode: str):
    if mode == "fast":
        return _fast_selection_reason(plan)
    if mode == "normal":
        return _normal_selection_reason(plan)
    if mode == "hard":
        return _hard_selection_reason(plan)
    return True, "include: explicit legacy pipeline"


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
    if family == "document" and extension in {"docx", "rtf", "doc"} and (
        explicit_name_signal or employee_context or "/прочее/" in folded_path
    ):
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


def _normal_selection_reason(plan):
    family = plan.family or "unknown"

    if plan.skip_reason:
        return False, f"skip: planner skipped file ({plan.skip_reason})"
    if family == "archive":
        return False, "skip: archive needs separate safe unpacking policy"
    if family == "presentation":
        return False, "skip: presentation deferred outside normal mode"
    if family == "image":
        return False, "skip: image OCR is reserved for hard mode"
    if family in {"text", "structured", "spreadsheet", "document", "web", "executable", "video"}:
        return True, f"include: normal {family} extraction"
    return False, "skip: no normal-mode extractor"


def _hard_selection_reason(plan):
    family = plan.family or "unknown"
    if family in {"image", "presentation"} and not plan.skip_reason:
        return True, f"include: hard OCR candidate ({family})"
    return _normal_selection_reason(plan)


def _apply_hard_ocr_budget(plans, max_ocr_files: int):
    if max_ocr_files <= 0:
        return [replace(plan, escalation_steps=[]) for plan in plans], []

    scored = []
    for plan in plans:
        if not plan.escalation_steps:
            continue
        score = _ocr_candidate_score(plan)
        if score > 0:
            scored.append((score, plan.path, plan))

    targets = {
        path
        for _, path, _ in sorted(scored, key=lambda item: (-item[0], item[1]))[:max_ocr_files]
    }

    planned = [
        plan if plan.path in targets else replace(plan, escalation_steps=[])
        for plan in plans
    ]
    decisions = [
        {
            "plan": plan,
            "include": plan.path in targets,
            "reason": f"ocr target score {score:.0f}" if plan.path in targets else f"ocr skipped by budget score {score:.0f}",
            "score": score,
        }
        for score, _, plan in sorted(scored, key=lambda item: (-item[0], item[1]))
    ]
    return planned, decisions


def _ocr_candidate_score(plan) -> float:
    family = plan.family or ""
    extension = plan.extension or ""
    folded_path = plan.path.casefold()
    metadata = plan.metadata or {}
    score = 0.0

    if family in {"image", "video"}:
        score += _ocr_candidate_score_value("media_family")
    if family == "document" and extension == "pdf":
        score += _ocr_candidate_score_value("pdf_document")
    if family == "presentation":
        score += _ocr_candidate_score_value("presentation")
    if extension in {"tif", "tiff"}:
        score += _ocr_candidate_score_value("tif_extension")
    if metadata.get("suspicious_name"):
        score += _ocr_candidate_score_value("suspicious_name")
    if "архив сканы" in folded_path:
        score += _ocr_candidate_score_value("scan_archive")
    if metadata.get("high_ocr_context"):
        score += _ocr_candidate_score_value("high_ocr_context")
    if any(keyword in folded_path for keyword in TRIAGE_OCR_PRIVATE_KEYWORDS):
        score += _ocr_candidate_score_value("private_keyword")
    if any(keyword in folded_path for keyword in TRIAGE_OCR_PUBLIC_PENALTY_KEYWORDS):
        score += _ocr_candidate_score_value("public_context_penalty")
    return score


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
    mode: str,
    review_report: str = "",
    ocr_decisions=None,
    ml_enabled: bool = False,
    max_candidates=None,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    scan_counter = Counter(_scan_type_key(item) for item in scan_results)
    selection_decisions = fast_decisions or [{"plan": plan, "include": True, "reason": "include: explicit legacy pipeline"} for plan in extraction_plans]
    ocr_decisions = ocr_decisions or []
    selected_reason_counter = Counter(item["reason"] for item in selection_decisions if item["include"])
    skipped_reason_counter = Counter(item["reason"] for item in selection_decisions if not item["include"])
    selected_type_counter = Counter((item["plan"].family or "unknown", item["plan"].extension or "unknown") for item in selection_decisions if item["include"])
    skipped_type_counter = Counter((item["plan"].family or "unknown", item["plan"].extension or "unknown") for item in selection_decisions if not item["include"])
    triage_band_counter = Counter(_score_band(item.get("score", 0)) for item in selection_decisions if "score" in item)
    extraction_summary = er.summarize_extraction_results(extraction_results)
    pii_summary = pii.summarize_pii_results(pii_results)
    ocr_target_counter = Counter(item["reason"] for item in ocr_decisions if item["include"])
    ocr_skipped_counter = Counter(item["reason"] for item in ocr_decisions if not item["include"])
    ner_status = pii.ner_runtime_status()

    lines = [
        "# Pipeline report",
        "",
        "## Mode",
        "",
        f"- Mode: `{mode}`",
        f"- Strategy: {MODE_DEFAULTS.get(mode, {}).get('description', 'Explicit legacy pipeline.')}",
        f"- Candidate pool limit: `{max_candidates if max_candidates is not None else 'unbounded'}`",
        f"- ML/NER requested: `{ml_enabled}`",
        f"- ML/NER status: `{ner_status.get('status', 'not_used')}` {ner_status.get('message', '')}".rstrip(),
        "",
        "## Outputs",
        "",
        f"- Submit paths: `{len(submit_lines)}`",
        f"- Risk threshold: `{threshold}`",
        f"- Review report: `{review_report or 'not requested'}`",
        "",
        "## Scan",
        "",
        f"- Total files: `{len(scan_results)}`",
        f"- Planned files: `{len(plans)}`",
        f"- Extracted candidates: `{len(extraction_plans)}`",
        f"- Files with extracted text: `{extraction_summary['files_with_text']}`",
        f"- Files with PII evidence: `{pii_summary['files_with_pii']}`",
        "",
        "| type | count |",
        "|---|---:|",
    ]

    for item, count in scan_counter.most_common():
        lines.append(f"| {item} | {count} |")

    lines.extend(["", "## Candidate Selection", ""])
    lines.extend(_counter_table("Selected reasons", selected_reason_counter))
    lines.extend([""])
    lines.extend(_counter_table("Skipped reasons", skipped_reason_counter))
    lines.extend([""])
    lines.extend(_counter_table("Selected type/family", selected_type_counter))
    lines.extend([""])
    lines.extend(_counter_table("Skipped type/family", skipped_type_counter, limit=25))
    if triage_band_counter:
        lines.extend([""])
        lines.extend(_counter_table("Triage score bands", triage_band_counter, limit=20))

    triage_rejected = [
        item
        for item in selection_decisions
        if not item["include"] and item.get("score", 0) > 0 and not item["reason"].startswith("skip: planner")
    ]
    if triage_rejected:
        lines.extend(["", "### Top Rejected By Triage", "", "| score | bucket | path | reason | signals |", "|---:|---|---|---|---|"])
        for item in sorted(triage_rejected, key=lambda value: (-value.get("score", 0), value["plan"].path))[:80]:
            lines.append(
                f"| {item.get('score', 0):.1f} | `{item.get('bucket', '')}` | `{item['plan'].path}` | {item['reason']} | {_format_signals(item.get('signals', []))} |"
            )

    if ocr_decisions:
        lines.extend(["", "## Hard OCR Budget", ""])
        lines.extend(_counter_table("OCR selected", ocr_target_counter, limit=20))
        lines.extend([""])
        lines.extend(_counter_table("OCR skipped", ocr_skipped_counter, limit=20))
        lines.extend(["", "| path | OCR decision | score |", "|---|---|---:|"])
        for item in ocr_decisions[:100]:
            lines.append(f"| `{item['plan'].path}` | {item['reason']} | {item.get('score', 0):.0f} |")

    lines.extend(["", "## Extraction", ""])
    lines.extend(_counter_table("Extractors", Counter(extraction_summary["extractors"])))
    lines.extend([""])
    lines.extend(_counter_table("Skipped steps", Counter(extraction_summary["skipped_steps"])))
    lines.extend([""])
    lines.extend(_counter_table("Failed steps", Counter(extraction_summary["failed_steps"])))

    lines.extend(["", "## PII Evidence", ""])
    lines.extend(_counter_table("Categories", Counter(pii_summary["categories"])))

    lines.extend(["", "## Selected Candidates", "", "| score | bucket | path | reason | signals |", "|---:|---|---|---|---|"])
    for item in selection_decisions:
        if item["include"]:
            lines.append(
                f"| {item.get('score', 0):.1f} | `{item.get('bucket', '')}` | `{item['plan'].path}` | {item['reason']} | {_format_signals(item.get('signals', []))} |"
            )

    lines.extend(["", "## Submit", "", "| score | submit | type | categories | rules |", "|---:|---|---|---|---|"])
    for assessment in sorted([item for item in assessments if item.score >= threshold], key=lambda item: item.submit_path):
        categories = ", ".join(f"{key}:{value}" for key, value in list(assessment.categories.items())[:6])
        rules = "; ".join(f"{hit.rule}({hit.score_delta:+.0f})" for hit in assessment.rule_hits[:6])
        lines.append(f"| {assessment.score:.1f} | `{assessment.submit_path}` | {assessment.document_type} | {categories} | {rules} |")

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


def _score_band(score: float) -> str:
    value = float(score or 0)
    lower = int(value // 25) * 25
    upper = lower + 24
    return f"{lower}-{upper}"


def _format_signals(signals) -> str:
    if not signals:
        return ""
    return ", ".join(str(signal) for signal in list(signals)[:8])


def _scan_type_key(scan_result):
    extension = (scan_result.get("extension") or "unknown").upper()
    mime = scan_result.get("mime") or "unknown"
    return f"{extension} ({mime})"


def run(args: argparse.Namespace) -> int:
    _configure_default_mode(args)

    try:
        share_root = fs.resolve_scan_root(args.folder)
        files_stream = fs.traverse_data_folder(str(share_root))
        scan_results = fs.count_and_report_files(files_stream)
        if args.scan_only:
            raise SystemExit(0)
        needs_risk = bool(args.risk or args.submit or args.risk_report or args.pipeline_report or args.review_report)
        if args.plan or args.extract or args.detect_pii or needs_risk:
            plans = list(ep.plan_extractions(scan_results))
        selection_decisions = []
        ocr_decisions = []
        if args.plan:
            ep.print_plan_report(plans)
        if args.extract or args.detect_pii or needs_risk:
            extraction_plans = plans
            if args.mode:
                extraction_plans, selection_decisions = _mode_candidate_selection(
                    extraction_plans,
                    args.mode,
                    max_candidates=args.max_candidates,
                )
                print(f"\n{args.mode.upper()} mode: triage выбрал {len(extraction_plans)} кандидатов из {len(plans)} файлов.")
            if args.extract_limit:
                extraction_plans = extraction_plans[: args.extract_limit]
                print(f"Smoke limit: обработка первых {len(extraction_plans)} кандидатов после triage.")
            include_escalations = bool(args.ocr)
            if args.mode == "hard":
                extraction_plans, ocr_decisions = _apply_hard_ocr_budget(extraction_plans, args.max_ocr_files)
                include_escalations = True
                targeted = sum(1 for item in ocr_decisions if item["include"])
                print(f"HARD OCR budget: OCR разрешен для {targeted} файлов из {len(ocr_decisions)} кандидатов.")
            elif args.mode:
                include_escalations = bool(MODE_DEFAULTS[args.mode]["include_escalations"] or args.ocr)
            results = list(er.run_extraction_plans(extraction_plans, include_escalations=include_escalations))
        if args.extract:
            er.print_extraction_report(results)
        if args.detect_pii or needs_risk:
            pii_results = pii.scan_extraction_results(
                results,
                use_ner=bool(args.ml),
                ner_file_limit=args.ml_max_files,
            )
        if args.detect_pii:
            pii.print_pii_report(pii_results)
        if needs_risk:
            assessments = risk.assess_risks(pii_results, extraction_plans, results, str(share_root), mode=args.mode or "legacy")
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
        if args.review_report:
            risk.write_review_report(assessments, args.review_report, threshold=args.risk_threshold)
            print(f"Review report записан: {args.review_report}")
        if args.pipeline_report:
            _write_pipeline_report(
                output_path=args.pipeline_report,
                scan_results=scan_results,
                plans=plans,
                extraction_plans=extraction_plans,
                fast_decisions=selection_decisions,
                extraction_results=results,
                pii_results=pii_results,
                assessments=assessments,
                threshold=args.risk_threshold,
                submit_lines=lines,
                mode=args.mode or "legacy",
                review_report=args.review_report or "",
                ocr_decisions=ocr_decisions,
                ml_enabled=bool(args.ml),
                max_candidates=args.max_candidates,
            )
            print(f"Pipeline report записан: {args.pipeline_report}")
    except FileNotFoundError as exc:
        print(exc)
        return 1
    return 0


def main(argv=None) -> int:
    return run(_parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
