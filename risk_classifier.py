from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from extraction_planner import ExtractionPlan
from pii_detector import PiiFileResult


DEFAULT_SUBMIT_THRESHOLD = 120.0

HIGH_RISK_CATEGORIES = {
    "bank_card",
    "cvv",
    "passport_rf",
    "snils",
    "inn_person",
    "mrz",
}

SPECIAL_CATEGORIES = {
    "health_data",
    "biometric_data",
    "religion",
    "political_views",
    "nationality",
}

CATEGORY_WEIGHTS = {
    "cvv": 90,
    "mrz": 80,
    "bank_card": 65,
    "passport_rf": 60,
    "snils": 55,
    "inn_person": 45,
    "bank_account": 40,
    "birth_date": 30,
    "health_data": 30,
    "biometric_data": 30,
    "address": 18,
    "phone": 12,
    "email": 10,
    "fio": 8,
    "inn_legal": 8,
    "bik": 5,
    "religion": 25,
    "political_views": 25,
    "nationality": 25,
}

SUSPICIOUS_PATH_KEYWORDS = (
    "выгруз",
    "subscribers",
    "subscriber",
    "backup",
    "dump",
    "full",
    "scan",
    "скан",
    "паспорт",
    "passport",
    "анкета",
    "заявка",
    "пропуск",
    "дмс",
    "dms",
    "личн",
    "копия",
    "card",
    "карта",
)

BENIGN_PATH_KEYWORDS = (
    "документы партнеров",
    "договор",
    "приказ",
    "распоряж",
    "свидетельство",
    "policy",
    "privacy",
    "terms",
    "rules",
    "agreement",
    "version",
    "brandbook",
    "instruction",
    "regulation",
    "положение",
    "устав",
    "отчет",
    "отчёт",
    "samoobsled",
    "mandatory_disclosure",
    "disclosure",
    "ukaz",
    "fz",
    "фз",
    "закон",
    "координаты",
    "публичн",
    "program",
    "программа",
)

BUSINESS_REQUISITE_CATEGORIES = {"inn_legal", "bik", "bank_account", "email", "phone", "address"}


@dataclass
class RiskRuleHit:
    rule: str
    score_delta: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    file_path: str
    submit_path: str
    score: float
    level: str
    categories: Dict[str, int]
    rule_hits: List[RiskRuleHit] = field(default_factory=list)
    recommendation: str = "manual_review"
    document_type: str = "unknown"

    @property
    def include_default(self) -> bool:
        return self.score >= DEFAULT_SUBMIT_THRESHOLD

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["rule_hits"] = [hit.to_dict() for hit in self.rule_hits]
        data["include_default"] = self.include_default
        return data


def assess_risks(
    pii_results: Iterable[PiiFileResult],
    plans: Iterable[ExtractionPlan],
    extraction_results: Iterable[Any],
    share_root: str,
) -> List[RiskAssessment]:
    plans_by_path = {plan.path: plan for plan in plans}
    extraction_by_path = {result.path: result for result in extraction_results}

    assessments = [
        assess_file_risk(
            pii_result=result,
            plan=plans_by_path.get(result.file_path),
            extraction_result=extraction_by_path.get(result.file_path),
            share_root=share_root,
        )
        for result in pii_results
    ]
    return sorted(assessments, key=lambda item: (item.score, sum(item.categories.values())), reverse=True)


def assess_file_risk(
    pii_result: PiiFileResult,
    plan: Optional[ExtractionPlan],
    extraction_result: Optional[Any],
    share_root: str,
) -> RiskAssessment:
    categories = pii_result.categories
    hits: List[RiskRuleHit] = []

    score = 0.0
    for category, count in categories.items():
        weight = CATEGORY_WEIGHTS.get(category, 3)
        delta = min(weight + max(0, count - 1) * min(weight * 0.12, 8), weight * 3.5)
        score += delta
        if category in HIGH_RISK_CATEGORIES or category in SPECIAL_CATEGORIES:
            hits.append(RiskRuleHit(f"category:{category}", delta, f"{category}: {count} находок."))

    path = pii_result.file_path
    folded_path = path.casefold()
    total_count = sum(categories.values())
    category_count = len(categories)
    plan_strategy = plan.strategy if plan else ""
    family = plan.family if plan else None
    extension = plan.extension if plan else None

    if any(category in categories for category in HIGH_RISK_CATEGORIES):
        delta = 35
        score += delta
        hits.append(RiskRuleHit("high_risk_identifier", delta, "Есть государственный идентификатор, карта, CVV или MRZ."))

    if categories.get("bank_card", 0) >= 5:
        delta = 35
        score += delta
        hits.append(RiskRuleHit("mass_bank_cards", delta, "Много номеров банковских карт."))

    if categories.get("snils", 0) >= 5:
        delta = 30
        score += delta
        hits.append(RiskRuleHit("mass_snils", delta, "Много валидных СНИЛС."))

    if categories.get("fio", 0) and _has_any(categories, ("passport_rf", "snils", "inn_person", "birth_date", "bank_card")):
        delta = 30
        score += delta
        hits.append(RiskRuleHit("person_profile_combo", delta, "ФИО сочетается с сильными идентификаторами."))

    if categories.get("fio", 0) and _has_any(categories, ("phone", "email", "address")) and category_count >= 3:
        delta = 18
        score += delta
        hits.append(RiskRuleHit("contact_profile_combo", delta, "ФИО сочетается с контактными или адресными данными."))

    if _has_any(categories, SPECIAL_CATEGORIES):
        delta = 20
        score += delta
        hits.append(RiskRuleHit("special_categories", delta, "Есть специальные категории или биометрические признаки."))

    if _looks_like_table_or_export(plan_strategy, family, extension) and total_count >= 100:
        delta = 28
        score += delta
        hits.append(RiskRuleHit("mass_table_pii", delta, "Массовая таблица или выгрузка с большим числом ПДн."))

    if _looks_like_table_or_export(plan_strategy, family, extension) and _has_any(categories, HIGH_RISK_CATEGORIES):
        delta = 35
        score += delta
        hits.append(RiskRuleHit("sensitive_export", delta, "Табличный/выгрузочный формат содержит чувствительные идентификаторы."))

    matched_suspicious = [keyword for keyword in SUSPICIOUS_PATH_KEYWORDS if keyword in folded_path]
    if matched_suspicious:
        delta = min(25, 8 + 4 * len(matched_suspicious))
        score += delta
        hits.append(RiskRuleHit("suspicious_path", delta, f"Подозрительный путь/имя: {', '.join(matched_suspicious[:4])}."))

    if pii_result.has_pii and ("мои бумажки" in folded_path or "employes" in folded_path or "employees" in folded_path):
        delta = 50
        score += delta
        hits.append(RiskRuleHit("informal_employee_folder", delta, "ПДн лежат в неформальной employee-папке."))

    if plan and plan.metadata.get("high_ocr_context") and pii_result.has_pii:
        delta = 10
        score += delta
        hits.append(RiskRuleHit("high_ocr_context", delta, "Файл находится в контексте сканов/выгрузок."))

    if _has_unsupported_sensitive_context(extraction_result, plan) and not pii_result.has_pii:
        delta = 15
        score += delta
        hits.append(RiskRuleHit("unread_suspicious_file", delta, "Файл не прочитан, но путь/формат выглядит подозрительно."))

    matched_benign = [keyword for keyword in BENIGN_PATH_KEYWORDS if keyword in folded_path]
    if matched_benign and not _has_any(categories, HIGH_RISK_CATEGORIES) and total_count < 50:
        delta = -25
        score += delta
        hits.append(RiskRuleHit("likely_business_context", delta, f"Похоже на деловой/публичный документ: {', '.join(matched_benign[:3])}."))

    if matched_benign and _business_requisites_only(categories):
        delta = -45
        score += delta
        hits.append(RiskRuleHit("business_requisites_only", delta, "Похоже на легитимные реквизиты организации без профиля физлица."))

    if matched_benign and not matched_suspicious and not _looks_like_table_or_export(plan_strategy, family, extension):
        noisy_sensitive = _has_any(categories, ("bank_card", "snils", "inn_legal")) and not categories.get("fio")
        if noisy_sensitive:
            delta = -120
            score += delta
            hits.append(RiskRuleHit("likely_public_number_noise", delta, "Публичный/нормативный документ с числовыми совпадениями без ФИО."))

    if not pii_result.has_pii:
        score = min(score, 25)

    score = max(0.0, round(score, 2))
    return RiskAssessment(
        file_path=path,
        submit_path=submit_path(path, share_root),
        score=score,
        level=_risk_level(score),
        categories=categories,
        rule_hits=hits,
        recommendation=_recommendation(score),
        document_type=_document_type(plan, categories, folded_path),
    )


def select_for_submit(
    assessments: Iterable[RiskAssessment],
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
) -> List[RiskAssessment]:
    selected = [assessment for assessment in assessments if assessment.score >= threshold]
    return sorted(selected, key=lambda item: item.submit_path)


def write_submit_file(
    assessments: Iterable[RiskAssessment],
    output_path: str,
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
) -> List[str]:
    selected = select_for_submit(assessments, threshold=threshold)
    lines = [assessment.submit_path for assessment in selected]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return lines


def write_risk_report(
    assessments: Iterable[RiskAssessment],
    output_path: str,
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
    limit: int = 200,
) -> None:
    assessment_list = sorted(assessments, key=lambda item: item.score, reverse=True)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Risk report",
        "",
        f"Submit threshold: `{threshold}`",
        f"Total assessed files: `{len(assessment_list)}`",
        f"Selected for submit: `{sum(1 for item in assessment_list if item.score >= threshold)}`",
        "",
        "| score | submit | type | categories | rules |",
        "|---:|---|---|---|---|",
    ]

    for assessment in assessment_list[:limit]:
        categories = ", ".join(f"{key}:{value}" for key, value in list(assessment.categories.items())[:6])
        rules = "; ".join(hit.rule for hit in assessment.rule_hits[:5])
        lines.append(
            f"| {assessment.score:.1f} | `{assessment.submit_path}` | {assessment.document_type} | {categories} | {rules} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarize_risks(
    assessments: Iterable[RiskAssessment],
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
) -> Dict[str, Any]:
    assessment_list = list(assessments)
    selected = [item for item in assessment_list if item.score >= threshold]
    level_counter = Counter(item.level for item in assessment_list)
    category_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()

    for item in selected:
        category_counter.update(item.categories)
        rule_counter.update(hit.rule for hit in item.rule_hits)

    return {
        "total": len(assessment_list),
        "selected": len(selected),
        "threshold": threshold,
        "levels": dict(level_counter.most_common()),
        "selected_categories": dict(category_counter.most_common()),
        "selected_rules": dict(rule_counter.most_common()),
        "top": [
            {
                "score": item.score,
                "submit_path": item.submit_path,
                "categories": item.categories,
                "rules": [hit.rule for hit in item.rule_hits[:5]],
            }
            for item in sorted(assessment_list, key=lambda value: value.score, reverse=True)[:10]
        ],
    }


def print_risk_report(
    assessments: Iterable[RiskAssessment],
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
) -> None:
    assessment_list = list(assessments)
    summary = summarize_risks(assessment_list, threshold=threshold)

    print("\n" + "=" * 60)
    print("ОЦЕНКА РИСКА")
    print("=" * 60)
    print(f"Файлов оценено:      {summary['total']}")
    print(f"Порог submit:        {summary['threshold']}")
    print(f"В submit:            {summary['selected']}")

    _print_counter("Уровни риска", summary["levels"])
    _print_counter("Категории в submit", summary["selected_categories"])
    _print_counter("Правила в submit", summary["selected_rules"])
    _print_top(summary["top"])


def submit_path(file_path: str, share_root: str) -> str:
    root = Path(share_root).resolve()
    path = Path(file_path).resolve()
    try:
        rel = path.relative_to(root)
        return "/" + rel.as_posix()
    except ValueError:
        parts = path.parts
        if "share" in parts:
            index = parts.index("share")
            return "/" + "/".join(parts[index + 1 :])
        return "/" + path.name


def _has_any(categories: Dict[str, int], names: Iterable[str]) -> bool:
    return any(categories.get(name, 0) > 0 for name in names)


def _business_requisites_only(categories: Dict[str, int]) -> bool:
    if not categories:
        return False
    return set(categories).issubset(BUSINESS_REQUISITE_CATEGORIES)


def _looks_like_table_or_export(strategy: str, family: Optional[str], extension: Optional[str]) -> bool:
    return (
        strategy in {"structured_parse", "table_parse"}
        or family in {"structured", "spreadsheet"}
        or extension in {"csv", "tsv", "json", "parquet", "xls", "xlsx"}
    )


def _has_unsupported_sensitive_context(extraction_result: Optional[Any], plan: Optional[ExtractionPlan]) -> bool:
    if not extraction_result or not plan:
        return False
    skipped = set(getattr(extraction_result, "skipped_steps", []))
    if not skipped.intersection({"image_prefilter", "legacy_doc_extractor", "legacy_office_extractor"}):
        return False
    path = plan.path.casefold()
    return any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS)


def _risk_level(score: float) -> str:
    if score >= 180:
        return "high"
    if score >= DEFAULT_SUBMIT_THRESHOLD:
        return "submit"
    if score >= 60:
        return "review"
    return "low"


def _recommendation(score: float) -> str:
    if score >= 90:
        return "manual_review_priority"
    if score >= DEFAULT_SUBMIT_THRESHOLD:
        return "manual_review"
    return "do_not_submit_baseline"


def _document_type(plan: Optional[ExtractionPlan], categories: Dict[str, int], folded_path: str) -> str:
    if categories.get("bank_card", 0) >= 5:
        return "card_dataset"
    if categories.get("snils", 0) >= 5:
        return "identifier_list"
    if _has_any(categories, ("passport_rf", "birth_date", "inn_person")) and categories.get("fio"):
        return "personal_profile"
    if "анкета" in folded_path or "заявка" in folded_path:
        return "form_or_request"
    if plan and _looks_like_table_or_export(plan.strategy, plan.family, plan.extension):
        return "table_or_export"
    if plan and plan.family == "image":
        return "image_candidate"
    if plan:
        return plan.family or "unknown"
    return "unknown"


def _print_counter(title: str, counter: Dict[str, int]) -> None:
    if not counter:
        return
    print("-" * 60)
    print(title)
    for key, value in counter.items():
        print(f"{key:<34} | {value}")


def _print_top(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print("-" * 60)
    print("Топ риска")
    for item in items:
        categories = ", ".join(f"{key}:{value}" for key, value in list(item["categories"].items())[:5])
        rules = ", ".join(item["rules"][:3])
        print(f"{item['score']:>6.1f} | {item['submit_path']:<58} | {categories} | {rules}")
