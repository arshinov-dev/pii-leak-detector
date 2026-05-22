# leak_ml_scorer.py
"""
ML-слой оценки вероятности утечки ПДн.

Делает следующее:
  - собирает расширенный контекст вокруг ПДн (абзац, заголовок, табличный контекст);
  - строит TF-IDF по пути, документу и контекстам;
  - считает словарь {категория_ПДн -> tfidf_контекста};
  - извлекает структурные признаки (страницы, язык, папочный контекст);
  - обучает LogisticRegression (на real labels + pseudo-labels);
  - выдаёт leak_probability и объяснение для каждого файла.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Константы и словари
# ---------------------------------------------------------------------------

CONTEXT_RADIUS = 200        # символов вокруг ПДн (локальный контекст)
MAX_CONTEXT_CHARS = 6000    # суммарно на контексты одного файла
MAX_DOC_CHARS = 10000       # обрезка документа для TF-IDF

PATH_TFIDF_WEIGHT = 0.05
DOC_TFIDF_WEIGHT = 0.30
CTX_TFIDF_WEIGHT = 0.65

ALL_CATEGORIES = [
    "email", "phone", "snils", "inn_person", "inn_legal",
    "passport_rf", "bank_card", "bank_account", "bik", "cvv",
    "birth_date", "address", "fio", "mrz", "identity_document",
    "health_data", "biometric_data", "religion", "political_views",
    "nationality", "foreign_id",
]

HIGH_RISK_CATS = {"bank_card", "cvv", "passport_rf", "snils", "inn_person", "mrz"}
SPECIAL_CATS   = {"health_data", "biometric_data", "religion", "political_views", "nationality"}
CONTACT_CATS   = {"email", "phone", "address", "fio"}

_SUSPICIOUS_PATH = re.compile(
    r"выгруз|subscribers?|backup|dump|скан|паспорт|анкет|заявк|пропуск|"
    r"dms|дмс|личн|копи|card|карт|employe|сотрудник|бумажк",
    re.IGNORECASE,
)
_BENIGN_PATH = re.compile(
    r"policy|privacy|terms|rules|agreement|устав|отчет|disclosure|ukaz|"
    r"публичн|program|instruction|regulation|requisites|реквизит",
    re.IGNORECASE,
)

LANG_RE_RU = re.compile(r"[А-Яа-яЁё]")
LANG_RE_EN = re.compile(r"[A-Za-z]")

# ---------------------------------------------------------------------------
# Импорт типов из существующих модулей (runtime)
# ---------------------------------------------------------------------------

try:
    from pii_detector import PiiFileResult
except Exception:
    PiiFileResult = Any  # type: ignore

try:
    from extraction_planner import ExtractionPlan
except Exception:
    ExtractionPlan = Any  # type: ignore


# ---------------------------------------------------------------------------
# Датаклассы
# ---------------------------------------------------------------------------

@dataclass
class PiiContext:
    """Контекст вокруг одной найденной ПДн."""
    category: str
    context_text: str       # текст (абзац/строка + заголовок/подпись)
    page_or_sheet: Optional[int] = None


@dataclass
class FileFeatures:
    """Полный набор признаков одного файла."""
    file_path: str
    file_name: str
    extension: str
    size_bytes: int
    family: str

    # Структурные признаки
    page_count: int
    pages_with_pii: int
    avg_pii_per_page: float

    ru_share: float
    en_share: float
    other_share: float

    folder_pii_ratio: float
    folder_max_score: float

    # TF-IDF тексты
    path_text: str
    doc_text: str
    contexts_text: str

    # Числовые признаки
    total_pii_count: int
    category_count: int
    has_high_risk: bool
    has_special: bool
    max_confidence: float
    avg_confidence: float
    blocks_with_pii: int
    ocr_used: bool
    table_format: bool

    # Словарь {категория: tfidf_score_контекста}
    category_context_tfidf: Dict[str, float] = field(default_factory=dict)

    # Агрегаты по контекстам high/special/contact
    high_risk_context_tfidf: float = 0.0
    special_context_tfidf: float = 0.0
    contact_context_tfidf: float = 0.0
    mean_context_tfidf: float = 0.0
    max_context_tfidf: float = 0.0

    # Контексты ПДн
    pii_contexts: List[PiiContext] = field(default_factory=list)

    # pseudo-label (эвристика)
    pseudo_label: Optional[int] = None


@dataclass
class LeakMLResult:
    """Результат ML-скоринга одного файла."""
    file_path: str
    leak_probability: float
    ml_score: float             # 0–100
    top_features: List[Tuple[str, float]]
    explanation: str
    category_context_tfidf: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 0. Вспомогательные кастеры
# ---------------------------------------------------------------------------

def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# 1. Сбор расширенных контекстов ПДн
# ---------------------------------------------------------------------------

def _split_paragraphs(text: str) -> List[str]:
    """Грубо режем на абзацы по пустым строкам / двойным переводам."""
    chunks = re.split(r"\n\s*\n+", text)
    return [re.sub(r"\s+", " ", c).strip() for c in chunks if c.strip()]


def _best_paragraph(paragraphs: List[str], snippet: str) -> str:
    """Находим абзац, куда лучше всего вписывается snippet."""
    if not paragraphs:
        return snippet
    best = paragraphs[0]
    best_score = -1
    for p in paragraphs:
        score = len(set(snippet.split()) & set(p.split()))
        if score > best_score:
            best_score = score
            best = p
    return best


def _header_candidates(block, blocks: List[Any]) -> List[str]:
    """Поиск возможных заголовков рядом с блоком."""
    candidates = []
    page = getattr(block, "page_or_sheet", None)
    idx = getattr(block, "block_index", None)
    if idx is None:
        return candidates

    for b in blocks:
        if getattr(b, "block_index", None) >= idx:
            break
        if getattr(b, "page_or_sheet", None) != page:
            continue
        text = (getattr(b, "text", None) or "").strip()
        if not text:
            continue
        if len(text) <= 120:
            candidates.append(text)
    return candidates[-3:]


def collect_pii_contexts(
    pii_result: PiiFileResult,
    extraction_result: Any,
) -> List[PiiContext]:
    """
    Для каждого PiiFinding берём:
      - абзац/строку вокруг;
      - заголовок на странице;
      - табличный контекст (именя колонок) если доступны.
    """
    if extraction_result is None:
        return []

    blocks: List[Any] = list(getattr(extraction_result, "blocks", []))
    blocks_by_index: Dict[int, Any] = {
        b.block_index: b for b in blocks if getattr(b, "block_index", None) is not None
    }

    contexts: List[PiiContext] = []
    total_chars = 0

    table_columns_by_block: Dict[int, List[str]] = {}
    for b in blocks:
        meta = getattr(b, "metadata", None) or {}
        cols = meta.get("columns") or meta.get("header") or []
        if cols and isinstance(cols, list):
            table_columns_by_block[getattr(b, "block_index", -1)] = [str(c) for c in cols]

    for finding in pii_result.findings:
        if total_chars >= MAX_CONTEXT_CHARS:
            break

        block = blocks_by_index.get(finding.block_index)
        if block is None:
            continue

        text = (getattr(block, "text", None) or "").strip()
        if not text:
            continue

        snippet = text[:CONTEXT_RADIUS * 2 + 400]
        snippet = re.sub(r"\s+", " ", snippet).strip()

        paragraphs = _split_paragraphs(text)
        para = _best_paragraph(paragraphs, snippet)

        headers = _header_candidates(block, blocks)
        header_text = " ".join(headers[-2:]) if headers else ""

        cols = table_columns_by_block.get(finding.block_index, [])
        table_ctx = " | ".join(cols)

        combined_parts = [header_text, para, table_ctx]
        combined = " ".join(p for p in combined_parts if p).strip()
        if not combined:
            combined = snippet

        combined = combined[:CONTEXT_RADIUS * 2]

        if combined:
            contexts.append(PiiContext(
                category=finding.category,
                context_text=combined,
                page_or_sheet=finding.page_or_sheet,
            ))
            total_chars += len(combined)

    return contexts


# ---------------------------------------------------------------------------
# 2. Документ и путь в текстовой форме
# ---------------------------------------------------------------------------

def _path_to_text(file_path: str) -> str:
    p = Path(file_path)
    parts = list(p.parts) + [p.stem]
    tokens = []
    for part in parts:
        tokens.extend(re.split(r"[\W_\-\.]+", part.lower()))
    return " ".join(t for t in tokens if len(t) > 1)


def _doc_text(extraction_result: Any) -> str:
    if extraction_result is None:
        return ""
    parts = []
    total = 0
    for block in getattr(extraction_result, "blocks", []):
        t = (getattr(block, "text", None) or "").strip()
        if not t:
            continue
        remaining = MAX_DOC_CHARS - total
        parts.append(t[:remaining])
        total += len(t)
        if total >= MAX_DOC_CHARS:
            break
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 3. Языковые доли
# ---------------------------------------------------------------------------

def _lang_shares(text: str) -> Tuple[float, float, float]:
    """Оцениваем долю русских/английских/прочих символов в тексте."""
    if not text:
        return 0.0, 0.0, 0.0
    ru = len(LANG_RE_RU.findall(text))
    en = len(LANG_RE_EN.findall(text))
    total = len(text)
    other = max(total - ru - en, 0)
    s_ru = ru / total
    s_en = en / total
    s_other = other / total
    return float(s_ru), float(s_en), float(s_other)


# ---------------------------------------------------------------------------
# 4. Страницы и папочный контекст
# ---------------------------------------------------------------------------

def _page_stats(pii_result: PiiFileResult) -> Tuple[int, int, float]:
    """
    (page_count, pages_with_pii, avg_pii_per_page).

    Для табличных/строчных источников page_or_sheet может быть строкой
    вроде 'rows 751-1000'. В этом случае считаем, что есть одна
    условная "страница", чтобы не ломать признаки.
    """
    raw_pages = [f.page_or_sheet for f in pii_result.findings if f.page_or_sheet is not None]
    if not raw_pages:
        return 1, 0, 0.0

    numeric_pages: List[int] = []
    for p in raw_pages:
        # если уже int — просто добавляем
        if isinstance(p, int):
            numeric_pages.append(p)
            continue
        # если строка — пробуем вытащить цифры
        if isinstance(p, str):
            nums = re.findall(r"\d+", p)
            if nums:
                try:
                    numeric_pages.append(int(nums[0]))
                    continue
                except ValueError:
                    pass
        # если не получилось — игнорируем
        continue

    if not numeric_pages:
        # вообще нет нормальных чисел, считаем всё на одной "странице"
        page_count = 1
        pages_with_pii = 1
        avg_pii = len(raw_pages) / 1.0
        return page_count, pages_with_pii, float(round(avg_pii, 3))

    page_count = max(numeric_pages)
    pages_with_pii = len(set(numeric_pages))
    avg_pii = len(numeric_pages) / max(pages_with_pii, 1)
    return int(page_count), int(pages_with_pii), float(round(avg_pii, 3))


def compute_folder_context(
    pii_results: Iterable[PiiFileResult],
    heuristic_assessments: Iterable[Any],
) -> Dict[str, Tuple[float, float]]:
    """
    Строит карту: папка -> (folder_pii_ratio, folder_max_score)
    """
    path_to_score = {a.file_path: float(a.score) for a in heuristic_assessments}
    folder_files: Dict[str, List[str]] = {}
    folder_with_pii: Dict[str, int] = {}
    folder_max: Dict[str, float] = {}

    for pr in pii_results:
        path = Path(pr.file_path)
        folder = str(path.parent)
        folder_files.setdefault(folder, []).append(pr.file_path)
        if pr.has_pii:
            folder_with_pii[folder] = folder_with_pii.get(folder, 0) + 1
        score = path_to_score.get(pr.file_path, 0.0)
        folder_max[folder] = max(folder_max.get(folder, 0.0), score)

    result: Dict[str, Tuple[float, float]] = {}
    for folder, files in folder_files.items():
        total = len(files)
        pii_cnt = folder_with_pii.get(folder, 0)
        ratio = pii_cnt / total if total else 0.0
        max_score = folder_max.get(folder, 0.0)
        result[folder] = (float(round(ratio, 3)), float(round(max_score, 1)))
    return result


# ---------------------------------------------------------------------------
# 5. Фича-извлечение для одного файла
# ---------------------------------------------------------------------------

def _has_ocr(extraction_result: Any) -> bool:
    if extraction_result is None:
        return False
    for step in getattr(extraction_result, "steps_used", []):
        if "ocr" in str(step).lower():
            return True
    for block in getattr(extraction_result, "blocks", []):
        if "ocr" in str(getattr(block, "extraction_method", "")).lower():
            return True
    return False


def extract_features(
    pii_result: PiiFileResult,
    plan: Optional[ExtractionPlan],
    extraction_result: Any,
    folder_context: Dict[str, Tuple[float, float]],
) -> FileFeatures:
    path = pii_result.file_path
    plan_family   = (plan.family   if plan else None) or "unknown"
    plan_ext      = (plan.extension if plan else None) or Path(path).suffix.lstrip(".").lower()
    plan_size     = int(getattr(plan, "size_bytes", 0) or 0)
    strategy      = (plan.strategy  if plan else "") or ""

    categories = pii_result.categories
    findings   = pii_result.findings

    total_pii   = int(sum(categories.values()))
    cat_count   = int(len(categories))
    has_high    = any(c in categories for c in HIGH_RISK_CATS)
    has_special = any(c in categories for c in SPECIAL_CATS)
    confidences = [float(getattr(f, "confidence", 0.0)) for f in findings] or [0.0]
    max_conf    = float(max(confidences))
    avg_conf    = float(sum(confidences) / len(confidences))

    ocr_used    = bool(_has_ocr(extraction_result))
    table_fmt   = bool(any(k in strategy for k in ("structured", "spreadsheet", "csv")) \
                  or plan_family in {"spreadsheet", "structured"})

    page_count, pages_with_pii, avg_pii_per_page = _page_stats(pii_result)

    doc_text = _doc_text(extraction_result)
    ru_share, en_share, other_share = _lang_shares(doc_text)

    folder = str(Path(path).parent)
    folder_pii_ratio, folder_max_score = folder_context.get(folder, (0.0, 0.0))

    pii_contexts = collect_pii_contexts(pii_result, extraction_result)
    contexts_text = " ".join(pc.context_text for pc in pii_contexts)[:MAX_CONTEXT_CHARS]

    return FileFeatures(
        file_path=path,
        file_name=Path(path).name,
        extension=plan_ext,
        size_bytes=plan_size,
        family=plan_family,
        page_count=page_count,
        pages_with_pii=pages_with_pii,
        avg_pii_per_page=avg_pii_per_page,
        ru_share=ru_share,
        en_share=en_share,
        other_share=other_share,
        folder_pii_ratio=float(folder_pii_ratio),
        folder_max_score=float(folder_max_score),
        path_text=_path_to_text(path),
        doc_text=doc_text,
        contexts_text=contexts_text,
        total_pii_count=total_pii,
        category_count=cat_count,
        has_high_risk=has_high,
        has_special=has_special,
        max_confidence=max_conf,
        avg_confidence=avg_conf,
        blocks_with_pii=int(getattr(pii_result, "blocks_with_pii", 0)),
        ocr_used=ocr_used,
        table_format=table_fmt,
        pii_contexts=pii_contexts,
    )


# ---------------------------------------------------------------------------
# 6. TF-IDF bundle
# ---------------------------------------------------------------------------

class TfidfBundle:
    """
    Три TF-IDF векторайзера:
      - путь
      - документ
      - контексты ПДн
    """

    def __init__(self, max_features: int = 300):
        self.path_vec = TfidfVectorizer(
            max_features=max_features,
            analyzer="word",
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
        )
        self.doc_vec = TfidfVectorizer(
            max_features=max_features,
            analyzer="word",
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
        )
        self.ctx_vec = TfidfVectorizer(
            max_features=max_features,
            analyzer="word",
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
        )
        self._fitted = False

    def fit(self, features: List[FileFeatures]) -> "TfidfBundle":
        self.path_vec.fit([f.path_text     for f in features])
        self.doc_vec .fit([f.doc_text      for f in features])
        self.ctx_vec .fit([f.contexts_text for f in features])
        self._fitted = True
        return self

    def transform_single(self, feat: FileFeatures) -> np.ndarray:
        assert self._fitted, "TfidfBundle not fitted"
        pv = self.path_vec.transform([feat.path_text]).toarray()[0]       * PATH_TFIDF_WEIGHT
        dv = self.doc_vec .transform([feat.doc_text]).toarray()[0]        * DOC_TFIDF_WEIGHT
        cv = self.ctx_vec .transform([feat.contexts_text]).toarray()[0]   * CTX_TFIDF_WEIGHT
        return np.concatenate([pv, dv, cv])

    def category_tfidf(self, feat: FileFeatures) -> Dict[str, float]:
        if not self._fitted:
            return {}
        by_cat: Dict[str, List[str]] = {}
        for pc in feat.pii_contexts:
            by_cat.setdefault(pc.category, []).append(pc.context_text)
        result: Dict[str, float] = {}
        for cat, texts in by_cat.items():
            merged = " ".join(texts)
            vec = self.ctx_vec.transform([merged]).toarray()[0]
            result[cat] = float(round(vec.mean(), 4))
        return result


# ---------------------------------------------------------------------------
# 7. Числовой вектор признаков
# ---------------------------------------------------------------------------

def _numeric_vector(feat: FileFeatures) -> np.ndarray:
    cat_flags = [1.0 if c in feat.category_context_tfidf else 0.0 for c in ALL_CATEGORIES]

    return np.array([
        math.log1p(_to_int(feat.total_pii_count)),
        _to_int(feat.category_count),
        float(bool(feat.has_high_risk)),
        float(bool(feat.has_special)),
        _to_float(feat.max_confidence),
        _to_float(feat.avg_confidence),
        _to_int(feat.blocks_with_pii),
        float(bool(feat.ocr_used)),
        float(bool(feat.table_format)),
        math.log1p(_to_int(feat.size_bytes)),
        _to_int(feat.page_count),
        _to_int(feat.pages_with_pii),
        _to_float(feat.avg_pii_per_page),
        _to_float(feat.ru_share),
        _to_float(feat.en_share),
        _to_float(feat.other_share),
        _to_float(feat.folder_pii_ratio),
        _to_float(feat.folder_max_score),
        _to_float(feat.high_risk_context_tfidf),
        _to_float(feat.special_context_tfidf),
        _to_float(feat.contact_context_tfidf),
        _to_float(feat.mean_context_tfidf),
        _to_float(feat.max_context_tfidf),
        *cat_flags,
    ], dtype=np.float32)


# ---------------------------------------------------------------------------
# 8. Pseudo-label (fallback)
# ---------------------------------------------------------------------------

def _pseudo_label(feat: FileFeatures, heuristic_score: float) -> int:
    return 1 if heuristic_score >= 80 else 0


# ---------------------------------------------------------------------------
# 9. Классификатор
# ---------------------------------------------------------------------------

class LeakClassifier:
    MODEL_FILE = "leak_classifier.json"

    def __init__(self, max_tfidf_features: int = 300):
        self.tfidf = TfidfBundle(max_features=max_tfidf_features)
        self.scaler = StandardScaler()
        self.clf = LogisticRegression(
            C=1.0,
            max_iter=500,
            class_weight="balanced",
            solver="lbfgs",
        )
        self._fitted = False

    def fit(
        self,
        features: List[FileFeatures],
        labels: Optional[List[int]] = None,
        heuristic_scores: Optional[List[float]] = None,
    ) -> "LeakClassifier":
        if labels is None:
            if heuristic_scores is None:
                raise ValueError("Нужны либо labels, либо heuristic_scores для pseudo-label")
            labels = [_pseudo_label(f, s) for f, s in zip(features, heuristic_scores)]

        self.tfidf.fit(features)

        for feat in features:
            feat.category_context_tfidf = self.tfidf.category_tfidf(feat)
            vals = list(feat.category_context_tfidf.values())
            feat.mean_context_tfidf = float(round(sum(vals) / len(vals), 4)) if vals else 0.0
            feat.max_context_tfidf = float(round(max(vals), 4)) if vals else 0.0
            feat.high_risk_context_tfidf = float(max(
                (feat.category_context_tfidf.get(c, 0.0) for c in HIGH_RISK_CATS),
                default=0.0,
            ))
            feat.special_context_tfidf = float(max(
                (feat.category_context_tfidf.get(c, 0.0) for c in SPECIAL_CATS),
                default=0.0,
            ))
            feat.contact_context_tfidf = float(max(
                (feat.category_context_tfidf.get(c, 0.0) for c in CONTACT_CATS),
                default=0.0,
            ))

        X = self._build_X(features)
        y = np.array(labels, dtype=np.int32)

        if len(set(y)) < 2:
            logger.warning("LeakClassifier: один класс в обучении, добавляем синтетический пример")
            X = np.vstack([X, np.zeros((1, X.shape[1]))])
            y = np.append(y, 1 - y[0])

        X_scaled = self.scaler.fit_transform(X)
        self.clf.fit(X_scaled, y)
        self._fitted = True
        return self

    def predict_proba(self, feat: FileFeatures) -> float:
        assert self._fitted
        feat.category_context_tfidf = self.tfidf.category_tfidf(feat)
        vals = list(feat.category_context_tfidf.values())
        feat.mean_context_tfidf = float(round(sum(vals) / len(vals), 4)) if vals else 0.0
        feat.max_context_tfidf = float(round(max(vals), 4)) if vals else 0.0
        feat.high_risk_context_tfidf = float(max(
            (feat.category_context_tfidf.get(c, 0.0) for c in HIGH_RISK_CATS),
            default=0.0,
        ))
        feat.special_context_tfidf = float(max(
            (feat.category_context_tfidf.get(c, 0.0) for c in SPECIAL_CATS),
            default=0.0,
        ))
        feat.contact_context_tfidf = float(max(
            (feat.category_context_tfidf.get(c, 0.0) for c in CONTACT_CATS),
            default=0.0,
        ))

        X = self._build_X([feat])
        X_scaled = self.scaler.transform(X)
        return float(self.clf.predict_proba(X_scaled)[0][1])

    def top_features(self, feat: FileFeatures, n: int = 8) -> List[Tuple[str, float]]:
        if not self._fitted:
            return []
        X = self._build_X([feat])
        X_scaled = self.scaler.transform(X)
        coefs = self.clf.coef_[0]
        contributions = coefs * X_scaled[0]
        names = self._feature_names()
        top_idx = np.argsort(np.abs(contributions))[::-1][:n]
        return [(names[i], float(round(contributions[i], 4))) for i in top_idx]

    def save(self, path: str) -> None:
        import pickle, base64
        state = {
            "pkl": base64.b64encode(pickle.dumps(self)).decode(),
        }
        Path(path).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("LeakClassifier сохранён в %s", path)

    @classmethod
    def load(cls, path: str) -> "LeakClassifier":
        import pickle, base64
        state = json.loads(Path(path).read_text(encoding="utf-8"))
        obj = pickle.loads(base64.b64decode(state["pkl"]))
        logger.info("LeakClassifier загружен из %s", path)
        return obj

    def _build_X(self, features: List[FileFeatures]) -> np.ndarray:
        tfidf_rows = np.vstack([self.tfidf.transform_single(f) for f in features])
        num_rows   = np.vstack([_numeric_vector(f) for f in features])
        return np.hstack([tfidf_rows, num_rows])

    def _feature_names(self) -> List[str]:
        pn = [f"path:{n}" for n in self.tfidf.path_vec.get_feature_names_out()]
        dn = [f"doc:{n}"  for n in self.tfidf.doc_vec .get_feature_names_out()]
        cn = [f"ctx:{n}"  for n in self.tfidf.ctx_vec .get_feature_names_out()]
        numeric = [
            "log_pii_count", "category_count", "has_high_risk", "has_special",
            "max_confidence", "avg_confidence", "blocks_with_pii",
            "ocr_used", "table_format", "log_size_bytes",
            "page_count", "pages_with_pii", "avg_pii_per_page",
            "ru_share", "en_share", "other_share",
            "folder_pii_ratio", "folder_max_score",
            "high_risk_ctx_tfidf", "special_ctx_tfidf",
            "contact_ctx_tfidf", "mean_ctx_tfidf", "max_ctx_tfidf",
            *[f"cat_flag:{c}" for c in ALL_CATEGORIES],
        ]
        return pn + dn + cn + numeric


# ---------------------------------------------------------------------------
# 10. Публичный API: score_all
# ---------------------------------------------------------------------------

def score_all(
    pii_results: Iterable[PiiFileResult],
    plans: Iterable[ExtractionPlan],
    extraction_results: Iterable[Any],
    heuristic_assessments: Iterable[Any],
    model_path: str = "out/leak_classifier.json",
) -> List[LeakMLResult]:
    """
    Главная точка входа:
      1. Строит folder_context (ratio, max_score).
      2. Извлекает FileFeatures для всех файлов.
      3. Загружает/обучает LeakClassifier.
      4. Возвращает LeakMLResult с вероятностью утечки.
    """
    pii_list      = list(pii_results)
    plans_map     = {p.path: p for p in plans}
    extract_map   = {r.path: r for r in extraction_results}
    heuristic_map = {a.file_path: float(a.score) for a in heuristic_assessments}

    folder_context = compute_folder_context(pii_list, heuristic_assessments)

    features: List[FileFeatures] = []
    for pr in pii_list:
        feat = extract_features(
            pii_result=pr,
            plan=plans_map.get(pr.file_path),
            extraction_result=extract_map.get(pr.file_path),
            folder_context=folder_context,
        )
        features.append(feat)

    heuristic_scores = [heuristic_map.get(f.file_path, 0.0) for f in features]

    clf = _load_or_fit(model_path, features, heuristic_scores)

    results: List[LeakMLResult] = []
    for feat, pr in zip(features, pii_list):
        prob = clf.predict_proba(feat)
        top  = clf.top_features(feat, n=8)
        results.append(LeakMLResult(
            file_path=pr.file_path,
            leak_probability=round(prob, 4),
            ml_score=round(prob * 100, 2),
            top_features=top,
            explanation=_explain(feat, prob, top),
            category_context_tfidf=feat.category_context_tfidf,
        ))

    return sorted(results, key=lambda r: r.leak_probability, reverse=True)


def _load_or_fit(
    model_path: str,
    features: List[FileFeatures],
    heuristic_scores: List[float],
) -> LeakClassifier:
    if Path(model_path).exists():
        try:
            return LeakClassifier.load(model_path)
        except Exception as exc:
            logger.warning("Не удалось загрузить модель %s: %s. Обучаем заново.", model_path, exc)

    clf = LeakClassifier()
    clf.fit(features, heuristic_scores=heuristic_scores)

    try:
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        clf.save(model_path)
    except Exception as exc:
        logger.warning("Не удалось сохранить модель: %s", exc)

    return clf


def _explain(feat: FileFeatures, prob: float, top: List[Tuple[str, float]]) -> str:
    level = "ВЫСОКИЙ" if prob >= 0.75 else ("СРЕДНИЙ" if prob >= 0.40 else "НИЗКИЙ")
    cats  = list(feat.category_context_tfidf.keys())[:5]
    top_f = ", ".join(f"{name}({w:+.3f})" for name, w in top[:4] if abs(w) > 0.001)
    return (
        f"Риск утечки: {level} ({prob:.1%}). "
        f"ПДн-категории: {', '.join(cats) or 'нет'}. "
        f"Ключевые признаки: {top_f or 'нет'}."
    )