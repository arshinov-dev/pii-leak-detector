from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys

import settings


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return _scan([])

    command = argv[0]
    if command == "scan":
        return _scan(argv[1:])
    if command == "doctor":
        return _doctor()
    if command == "init-config":
        return _init_config(argv[1:])
    if command in {"-h", "--help"}:
        _print_help()
        return 0

    # Backward-compatible shorthand: `pii-leak-detector share --mode normal`.
    return _scan(argv)


def _scan(argv: list[str]) -> int:
    from main import main as pipeline_main

    return pipeline_main(argv)


def _init_config(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="pii-leak-detector init-config",
        description="Copy the active detector_settings.json template to a target path.",
    )
    parser.add_argument("path", nargs="?", default="detector_settings.json")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing file.")
    args = parser.parse_args(argv)

    try:
        destination = settings.copy_settings_template(args.path, overwrite=args.force)
    except FileExistsError as exc:
        print(exc)
        return 1
    except FileNotFoundError as exc:
        print(exc)
        return 1

    print(f"Config written: {destination}")
    return 0


def _doctor() -> int:
    print("PII Leak Detector doctor")
    print(f"Python: {sys.version.split()[0]}")
    try:
        print(f"Settings: {settings.active_settings_path()}")
    except FileNotFoundError as exc:
        print(f"Settings: missing ({exc})")
        return 1

    checks = {
        "filetype": "filetype",
        "PyMuPDF": "fitz",
        "pyarrow": "pyarrow",
        "Pillow": "PIL",
        "OpenCV": "cv2",
        "pytesseract": "pytesseract",
        "python-pptx": "pptx",
        "Presidio": "presidio_analyzer",
        "spaCy": "spacy",
        "spaCy model": "xx_ent_wiki_sm",
    }
    failed = []
    for label, module in checks.items():
        ok = importlib.util.find_spec(module) is not None
        print(f"{label:<14} {'ok' if ok else 'missing'}")
        if not ok:
            failed.append(label)

    tesseract = shutil.which("tesseract")
    print(f"{'tesseract bin':<14} {tesseract or 'missing'}")
    if not tesseract:
        failed.append("tesseract binary")

    if failed:
        print("Missing optional/runtime pieces: " + ", ".join(failed))
        return 1
    return 0


def _print_help() -> None:
    print(
        "\n".join(
            [
                "PII Leak Detector",
                "",
                "Commands:",
                "  pii-leak-detector scan [folder] [options]   run the detection pipeline",
                "  pii-leak-detector doctor                    check Python/runtime dependencies",
                "  pii-leak-detector init-config [path]        copy detector_settings.json template",
                "",
                "Backward-compatible shorthand:",
                "  pii-leak-detector [folder] --mode fast",
                "",
                "Examples:",
                "  pii-leak-detector scan share --mode fast",
                "  pii-leak-detector scan /data/share --mode normal --max-candidates 250",
                "  pii-leak-detector init-config configs/detector_settings.json",
            ]
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
