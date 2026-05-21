import argparse

import extraction_planner as ep
import extraction_runner as er
import file_search as fs


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
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    try:
        files_stream = fs.traverse_data_folder(args.folder)
        scan_results = fs.count_and_report_files(files_stream)
        if args.plan or args.extract:
            plans = list(ep.plan_extractions(scan_results))
        if args.plan:
            ep.print_plan_report(plans)
        if args.extract:
            extraction_plans = plans[: args.extract_limit] if args.extract_limit else plans
            results = list(er.run_extraction_plans(extraction_plans))
            er.print_extraction_report(results)
    except FileNotFoundError as exc:
        print(exc)
        raise SystemExit(1)
