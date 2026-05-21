import argparse

import extraction_planner as ep
import file_search as fs


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII leak detector pipeline")
    parser.add_argument("folder", nargs="?", default="share", help="Папка для сканирования.")
    parser.add_argument(
        "--plan",
        action="store_true",
        help="После инвентаризации построить и вывести сводку планов извлечения.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    try:
        files_stream = fs.traverse_data_folder(args.folder)
        scan_results = fs.count_and_report_files(files_stream)
        if args.plan:
            plans = list(ep.plan_extractions(scan_results))
            ep.print_plan_report(plans)
    except FileNotFoundError as exc:
        print(exc)
        raise SystemExit(1)
