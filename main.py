import argparse

import extraction_planner as ep
import extraction_runner as er
import file_search as fs
import pii_detector as pii
import risk_classifier as risk


FAST_SUBMIT_DEFAULT = "out/submit_fast.txt"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII leak detector pipeline")
    parser.add_argument("folder", nargs="?", default="share", help="Папка для сканирования.")
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
    return parser.parse_args()


def _fast_candidate_plans(plans):
    selected = []
    for plan in plans:
        family = plan.family
        extension = plan.extension
        metadata = plan.metadata
        folded_path = plan.path.casefold()

        if family in {"text", "structured", "spreadsheet", "video", "executable"}:
            selected.append(plan)
            continue

        if family == "document" and extension in {"docx", "rtf", "doc"}:
            if metadata.get("suspicious_name") or metadata.get("high_ocr_context") or "employes" in folded_path:
                selected.append(plan)
            continue

        if family == "web" and metadata.get("suspicious_name"):
            selected.append(plan)

    return selected


if __name__ == "__main__":
    args = _parse_args()
    if args.fast:
        args.risk = True
        if not args.submit:
            args.submit = FAST_SUBMIT_DEFAULT

    try:
        share_root = fs.resolve_scan_root(args.folder)
        files_stream = fs.traverse_data_folder(str(share_root))
        scan_results = fs.count_and_report_files(files_stream)
        needs_risk = bool(args.risk or args.submit or args.risk_report)
        if args.plan or args.extract or args.detect_pii or needs_risk:
            plans = list(ep.plan_extractions(scan_results))
        if args.plan:
            ep.print_plan_report(plans)
        if args.extract or args.detect_pii or needs_risk:
            extraction_plans = plans[: args.extract_limit] if args.extract_limit else plans
            if args.fast:
                extraction_plans = _fast_candidate_plans(extraction_plans)
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
        if args.risk_report:
            risk.write_risk_report(assessments, args.risk_report, threshold=args.risk_threshold)
            print(f"Risk report записан: {args.risk_report}")
    except FileNotFoundError as exc:
        print(exc)
        raise SystemExit(1)
