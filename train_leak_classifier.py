# train_leak_classifier.py
from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Any, Iterable

from file_search import detect_file_type
from extraction_planner import plan_extractions, ExtractionPlan
from extraction_runner import run_extraction_plans, ExtractionRunResult
from pii_detector import scan_extraction_results, PiiFileResult
from risk_classifier import assess_risks
from leak_ml_scorer import (
    extract_features,
    compute_folder_context,
    LeakClassifier,
)

SHARE_ROOT = "share"
LABELS_CSV = "out/train_labels_all.csv"
MODEL_PATH = "out/leak_classifier_supervised.json"


def load_labels(csv_path: str, share_root: str) -> Dict[str, int]:
    """
    Загружает метки из CSV:

        file_path,label

    Поддерживает:
      - абсолютные пути,
      - submit-пути от корня share (/Выгрузки/...).
    """
    labels: Dict[str, int] = {}
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Не найден файл с метками: {csv_path}")

    root = Path(share_root).resolve()
    root_str = str(root)

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row["file_path"].strip()
            label = int(row["label"])

            if raw.startswith("/absolute/path/to/share/"):
                rel = raw.replace("/absolute/path/to/share/", "", 1)
                abs_path = root / rel.lstrip("/")
            else:
                p = Path(raw)
                if p.is_absolute():
                    if str(p).startswith(root_str):
                        abs_path = p
                    else:
                        abs_path = p
                else:
                    rel = raw.lstrip("/")
                    abs_path = root / rel

            abs_path_resolved = str(abs_path.resolve())
            labels[abs_path_resolved] = label

    return labels


def walk_share_as_dicts(root: Path) -> List[Dict[str, Any]]:
    """
    Обходит share и вызывает detect_file_type для каждого файла.
    Возвращает список dict, как ожидает plan_extractions.
    """
    results: List[Dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        scan_dict = detect_file_type(str(path))
        results.append(scan_dict)
    return results


def run_all_extractions(plans: Iterable[ExtractionPlan]) -> List[ExtractionRunResult]:
    return list(run_extraction_plans(plans, include_escalations=False))


def main() -> None:
    share_root_path = Path(SHARE_ROOT).resolve()
    print(f"[train] SHARE_ROOT = {share_root_path}")

    # 1. Сканирование
    print("[train] Сканирование share/ ...")
    scan_results_dicts = walk_share_as_dicts(share_root_path)
    print(f"[train] Найдено файлов: {len(scan_results_dicts)}")

    # 2. Планирование
    print("[train] Планирование извлечения ...")
    plans: List[ExtractionPlan] = list(plan_extractions(scan_results_dicts))
    print(f"[train] Планов извлечения: {len(plans)}")

    # 3. Извлечение
    print("[train] Запуск извлечения ...")
    extraction_results: List[ExtractionRunResult] = run_all_extractions(plans)
    print(f"[train] Извлечений: {len(extraction_results)}")

    # 4. Детекция ПДн
    print("[train] Детекция ПДн ...")
    pii_results: List[PiiFileResult] = scan_extraction_results(extraction_results)
    print(f"[train] Файлов с результатами ПДн: {len(pii_results)}")

    # 5. Эвристический скоринг (для folder_context; в обучении не используем)
    print("[train] Эвристический risk-скоринг ...")
    heuristic_assessments = assess_risks(
        pii_results=pii_results,
        plans=plans,
        extraction_results=extraction_results,
        share_root=str(share_root_path),
        ml_results=None,
    )

    # 6. Метки от бота
    print(f"[train] Загрузка меток из {LABELS_CSV} ...")
    labels_by_path = load_labels(LABELS_CSV, share_root=str(share_root_path))
    print(f"[train] Размеченных файлов (бот): {len(labels_by_path)}")

    # 7. Признаки только для размеченных файлов
    print("[train] Подготовка признаков (только размеченные файлы) ...")
    folder_context = compute_folder_context(pii_results, heuristic_assessments)
    plans_map = {p.path: p for p in plans}
    extract_map = {r.path: r for r in extraction_results}

    features: List[Any] = []
    labels: List[int] = []

    for pr in pii_results:
        file_abs = str(Path(pr.file_path).resolve())
        if file_abs not in labels_by_path:
            continue

        feat = extract_features(
            pii_result=pr,
            plan=plans_map.get(pr.file_path),
            extraction_result=extract_map.get(pr.file_path),
            folder_context=folder_context,
        )
        features.append(feat)
        labels.append(labels_by_path[file_abs])

    if not features:
        print("Нет ни одного файла с обучающими метками. Проверь out/train_labels_all.csv")
        return

    print(f"[train] Обучаемся на {len(features)} размеченных файлов ...")

    # 8. Обучение supervised-модели
    clf = LeakClassifier()
    clf.fit(features, labels=labels, heuristic_scores=None)

    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    clf.save(MODEL_PATH)

    print(f"[train] Обучение завершено, модель сохранена в {MODEL_PATH}")


if __name__ == "__main__":
    main()