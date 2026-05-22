from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import unicodedata

from extraction_planner import ExtractionPlan
from pii_detector import PiiFileResult
import settings as cfg


DEFAULT_SUBMIT_THRESHOLD = float(cfg.get("risk.default_submit_threshold", 120.0))
RISK_LEVEL_HIGH = float(cfg.get("risk.risk_level_high", 180.0))
RISK_LEVEL_REVIEW = float(cfg.get("risk.risk_level_review", 60.0))
RECOMMENDATION_PRIORITY = float(cfg.get("risk.recommendation_priority", 90.0))
NO_PII_SCORE_CAP = float(cfg.get("risk.no_pii_score_cap", 25.0))
DEFAULT_REVIEW_FLOOR = float(cfg.get("runtime_defaults.review_floor", 35.0))
CATEGORY_WEIGHT_DEFAULT = float(cfg.get("risk.category_weight_default", 3))
CATEGORY_REPEAT_FACTOR = float(cfg.get("risk.category_repeat_factor", 0.12))
CATEGORY_REPEAT_CAP = float(cfg.get("risk.category_repeat_cap", 8))
CATEGORY_MAX_MULTIPLIER = float(cfg.get("risk.category_max_multiplier", 3.5))

HIGH_RISK_CATEGORIES = cfg.set_setting("risk.high_risk_categories")
SPECIAL_CATEGORIES = cfg.set_setting("risk.special_categories")
CATEGORY_WEIGHTS = cfg.get("risk.category_weights", {})
RULE_SCORES = cfg.get("risk.rule_scores", {})
SUSPICIOUS_PATH_SCORE = cfg.get("risk.suspicious_path_score", {})
SUSPICIOUS_PATH_KEYWORDS = cfg.tuple_setting("risk.suspicious_path_keywords")
BENIGN_PATH_KEYWORDS = cfg.tuple_setting("risk.benign_path_keywords")
BUSINESS_REQUISITE_CATEGORIES = cfg.set_setting("risk.business_requisite_categories")
BUSINESS_CONTACT_EXPORT_CATEGORIES = cfg.set_setting("risk.business_contact_export_categories")
LEGAL_ENTITY_EXPORT_CATEGORIES = cfg.set_setting("risk.legal_entity_export_categories")
OPERATIONAL_EXPORT_PATH_KEYWORDS = cfg.tuple_setting("risk.operational_export_path_keywords")
BILLING_FULL_DUMP_CONTEXTS = cfg.tuple_setting("risk.billing_full_dump_contexts")
PUBLIC_STRUCTURED_NOISE_NAMES = cfg.tuple_setting("risk.public_structured_noise_names")
SITE_DUMP_CONTEXTS = cfg.tuple_setting("risk.site_dump_contexts")


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
    mode: str = "legacy",
) -> List[RiskAssessment]:
    plans_by_path = {plan.path: plan for plan in plans}
    extraction_by_path = {result.path: result for result in extraction_results}

    assessments = [
        assess_file_risk(
            pii_result=result,
            plan=plans_by_path.get(result.file_path),
            extraction_result=extraction_by_path.get(result.file_path),
            share_root=share_root,
            mode=mode,
        )
        for result in pii_results
    ]
    return sorted(assessments, key=lambda item: (item.score, sum(item.categories.values())), reverse=True)


def assess_file_risk(
    pii_result: PiiFileResult,
    plan: Optional[ExtractionPlan],
    extraction_result: Optional[Any],
    share_root: str,
    mode: str = "legacy",
) -> RiskAssessment:
    categories = pii_result.categories
    hits: List[RiskRuleHit] = []

    score = 0.0
    for category, count in categories.items():
        weight = CATEGORY_WEIGHTS.get(category, CATEGORY_WEIGHT_DEFAULT)
        delta = min(
            weight + max(0, count - 1) * min(weight * CATEGORY_REPEAT_FACTOR, CATEGORY_REPEAT_CAP),
            weight * CATEGORY_MAX_MULTIPLIER,
        )
        score += delta
        if category in HIGH_RISK_CATEGORIES or category in SPECIAL_CATEGORIES:
            hits.append(RiskRuleHit(f"category:{category}", delta, f"{category}: {count} находок."))

    path = pii_result.file_path
    folded_path = _fold(path)
    total_count = sum(categories.values())
    category_count = len(categories)
    plan_strategy = plan.strategy if plan else ""
    family = plan.family if plan else None
    extension = plan.extension if plan else None
    table_or_export = _looks_like_table_or_export(plan_strategy, family, extension)
    table_hints = _table_semantic_summary(extraction_result)
    operational_contact_export = _looks_like_operational_contact_export(folded_path, categories, table_or_export)
    ocr_used = _has_ocr_text(extraction_result)
    embedded_document_payload = _has_embedded_document_payload(extraction_result)
    weak_card_noise = _weak_single_card_noise(categories, family, table_or_export, folded_path)
    strong_profile = _has_strong_person_profile(
        categories,
        family=family,
        ocr_used=ocr_used,
        weak_card_noise=weak_card_noise,
    )

    if _has_high_risk_identifier(categories, weak_card_noise):
        delta = _rule_score("high_risk_identifier", 35)
        score += delta
        hits.append(RiskRuleHit("high_risk_identifier", delta, "Есть государственный идентификатор, карта, CVV или MRZ."))

    if categories.get("identity_document", 0) and (family in {"image", "video"} or ocr_used):
        delta = _rule_score("identity_document_media", 95)
        score += delta
        hits.append(RiskRuleHit("identity_document_media", delta, "OCR/медиа содержит признаки удостоверения личности."))

    if categories.get("identity_document", 0) and family in {"document", "rtf", "web"}:
        delta = _rule_score("form_identity_document", 80)
        score += delta
        hits.append(RiskRuleHit("form_identity_document", delta, "Документ содержит признаки анкеты или удостоверения личности."))

    if embedded_document_payload:
        delta = _rule_score("embedded_identity_document_payload", 170)
        score += delta
        hits.append(RiskRuleHit("embedded_identity_document_payload", delta, "Бинарный файл содержит embedded image payload, похожий на документ личности."))

    if categories.get("bank_card", 0) >= 5:
        card_noise_export = (
            table_or_export
            and not _has_any(categories, ("passport_rf", "snils", "inn_person", "mrz", "cvv", "identity_document"))
            and not table_hints.get("sensitive_column_value")
            and not table_hints.get("identifier_column")
        )
        if not card_noise_export:
            delta = _rule_score("mass_bank_cards", 35)
            score += delta
            hits.append(RiskRuleHit("mass_bank_cards", delta, "Много номеров банковских карт."))

    if categories.get("snils", 0) >= 5:
        delta = _rule_score("mass_snils", 30)
        score += delta
        hits.append(RiskRuleHit("mass_snils", delta, "Много валидных СНИЛС."))

    if categories.get("fio", 0) and _has_profile_identifier(categories, weak_card_noise):
        delta = _rule_score("person_profile_combo", 30)
        score += delta
        hits.append(RiskRuleHit("person_profile_combo", delta, "ФИО сочетается с сильными идентификаторами."))

    if categories.get("fio", 0) and _has_any(categories, ("phone", "email", "address")) and category_count >= 3:
        delta = _rule_score("contact_profile_combo", 18)
        score += delta
        hits.append(RiskRuleHit("contact_profile_combo", delta, "ФИО сочетается с контактными или адресными данными."))

    if _has_any(categories, SPECIAL_CATEGORIES) and strong_profile:
        delta = _rule_score("special_categories", 20)
        score += delta
        hits.append(RiskRuleHit("special_categories", delta, "Есть специальные категории или биометрические признаки."))

    if table_or_export and total_count >= 100:
        delta = _rule_score("mass_table_pii", 28)
        score += delta
        hits.append(RiskRuleHit("mass_table_pii", delta, "Массовая таблица или выгрузка с большим числом ПДн."))

    if table_or_export and _has_any(categories, HIGH_RISK_CATEGORIES):
        delta = _rule_score("sensitive_export", 35)
        score += delta
        hits.append(RiskRuleHit("sensitive_export", delta, "Табличный/выгрузочный формат содержит чувствительные идентификаторы."))

    if mode in {"normal", "hard"} and table_or_export:
        if table_hints.get("identifier_column") or table_hints.get("sensitive_column_value"):
            delta = _rule_score("table_sensitive_schema", 45)
            score += delta
            hits.append(RiskRuleHit("table_sensitive_schema", delta, "Схема таблицы содержит колонки/значения сильных идентификаторов."))
        if not operational_contact_export and table_hints.get("physical_person_rows") and table_hints.get("person_type_column") and table_hints.get("person_name_column"):
            delta = _rule_score("table_physical_person_export", 65)
            score += delta
            hits.append(RiskRuleHit("table_physical_person_export", delta, "Выгрузка явно содержит строки физлиц и именные колонки."))
        if table_hints.get("physical_person_rows") and table_hints.get("person_name_column"):
            delta = _rule_score("table_physical_person_names", 42)
            score += delta
            hits.append(RiskRuleHit("table_physical_person_names", delta, "В таблице есть физлица и именные колонки."))
        if table_hints.get("person_name_column") and table_hints.get("address_column"):
            delta = _rule_score("table_name_address_schema", 34)
            score += delta
            hits.append(RiskRuleHit("table_name_address_schema", delta, "Схема таблицы связывает имена с адресными колонками."))
        if table_hints.get("person_name_column") and table_hints.get("contact_column"):
            delta = _rule_score("table_name_contact_schema", 26)
            score += delta
            hits.append(RiskRuleHit("table_name_contact_schema", delta, "Схема таблицы связывает имена с контактными колонками."))

    if operational_contact_export:
        delta = _rule_score("operational_contact_export", -85)
        score += delta
        hits.append(RiskRuleHit("operational_contact_export", delta, "Операционная/логистическая таблица содержит контактные поля без сильных идентификаторов."))

    if _looks_like_mass_name_only_export(categories, table_or_export):
        delta = _rule_score("mass_name_only_export", -45)
        score += delta
        hits.append(RiskRuleHit("mass_name_only_export", delta, "Массовая таблица с именами без контактов и сильных идентификаторов оставлена для review, не для submit."))

    if mode in {"normal", "hard"} and _looks_like_legal_entity_export_without_person(categories, table_or_export, table_hints, folded_path):
        delta = _rule_score("legal_entity_export_without_person", -130)
        score += delta
        hits.append(RiskRuleHit("legal_entity_export_without_person", delta, "Таблица похожа на реквизиты/контакты юрлиц без профилей физлиц."))

    if mode in {"normal", "hard"} and _looks_like_physical_name_only_review(categories, table_or_export, folded_path):
        delta = _rule_score("physical_name_only_review", -80)
        score += delta
        hits.append(RiskRuleHit("physical_name_only_review", delta, "Таблица с физлицами, но без сильных идентификаторов, оставлена для review."))

    matched_suspicious = [keyword for keyword in SUSPICIOUS_PATH_KEYWORDS if keyword in folded_path]
    if matched_suspicious:
        delta = min(
            _suspicious_path_score("cap", 25),
            _suspicious_path_score("base", 8) + _suspicious_path_score("per_keyword", 4) * len(matched_suspicious),
        )
        score += delta
        hits.append(RiskRuleHit("suspicious_path", delta, f"Подозрительный путь/имя: {', '.join(matched_suspicious[:4])}."))

    if pii_result.has_pii and ("мои бумажки" in folded_path or "employes" in folded_path or "employees" in folded_path):
        delta = _rule_score("informal_employee_folder", 50)
        score += delta
        hits.append(RiskRuleHit("informal_employee_folder", delta, "ПДн лежат в неформальной employee-папке."))

    if plan and plan.metadata.get("high_ocr_context") and pii_result.has_pii:
        delta = _rule_score("high_ocr_context", 10)
        score += delta
        hits.append(RiskRuleHit("high_ocr_context", delta, "Файл находится в контексте сканов/выгрузок."))

    if family == "image" and "архив сканы" in folded_path:
        delta = _rule_score("scan_archive_image", 55)
        score += delta
        hits.append(RiskRuleHit("scan_archive_image", delta, "Изображение из архива сканов требует приоритетной проверки."))

    if _has_unsupported_sensitive_context(extraction_result, plan) and not pii_result.has_pii:
        delta = _rule_score("unread_suspicious_file", 15)
        score += delta
        hits.append(RiskRuleHit("unread_suspicious_file", delta, "Файл не прочитан, но путь/формат выглядит подозрительно."))

    matched_benign = [keyword for keyword in BENIGN_PATH_KEYWORDS if keyword in folded_path]
    publicish_container = _looks_like_publicish_container(folded_path, family)

    if family == "video" and not pii_result.has_pii:
        delta = _rule_score("video_manual_review_candidate", 130)
        score += delta
        hits.append(RiskRuleHit("video_manual_review_candidate", delta, "Видео требует ручной проверки; OCR может содержать документ."))

    misc_public = _misc_public_bucket_without_context(folded_path, family, matched_suspicious)
    person_leak_signal = _has_person_leak_signal(categories, folded_path)
    if _looks_like_public_weak_form(folded_path, family, categories, table_or_export):
        delta = _rule_score("public_weak_form_template", -180)
        score += delta
        hits.append(RiskRuleHit("public_weak_form_template", delta, "Публичный шаблон/перечень без реального профиля физлица подавлен."))

    if _looks_like_public_structured_noise(folded_path, categories, table_or_export):
        delta = _rule_score("public_structured_noise", -220)
        score += delta
        hits.append(RiskRuleHit("public_structured_noise", delta, "Публичный JSON/таблица без связанного профиля физлица подавлены."))

    if _looks_like_site_dump_without_profile(folded_path, family, categories, table_or_export):
        delta = _rule_score("site_dump_without_profile", -180)
        score += delta
        hits.append(RiskRuleHit("site_dump_without_profile", delta, "Файл из выгрузки сайтов похож на публичный контент без профиля физлица."))

    if misc_public and not strong_profile and not person_leak_signal:
        delta = _rule_score("misc_public_bucket_without_context", -220)
        score += delta
        hits.append(RiskRuleHit("misc_public_bucket_without_context", delta, "Файл из прочего публичного массива без явного leak-контекста."))

    if family == "web" and not strong_profile:
        delta = _rule_score("web_snapshot_without_profile", -110)
        score += delta
        hits.append(RiskRuleHit("web_snapshot_without_profile", delta, "HTML-снимок без сильного профиля физлица похож на публичный веб-контент."))

    if (
        publicish_container
        and not matched_suspicious
        and not strong_profile
        and not table_or_export
        and not person_leak_signal
    ):
        delta = _rule_score("public_container_without_profile", -75)
        score += delta
        hits.append(RiskRuleHit("public_container_without_profile", delta, "Публичный/прочий контейнер без сильного профиля физлица."))

    if matched_benign and not strong_profile and not table_or_export:
        delta = _rule_score("benign_document_without_profile", -70)
        score += delta
        hits.append(RiskRuleHit("benign_document_without_profile", delta, f"Деловой/публичный документ без сильного профиля: {', '.join(matched_benign[:3])}."))

    if weak_card_noise:
        delta = _rule_score("weak_single_card_noise", -95)
        score += delta
        hits.append(RiskRuleHit("weak_single_card_noise", delta, "Одиночные Luhn-совпадения в документе/HTML без карточного контекста считаются шумом."))

    if matched_benign and not _has_any(categories, HIGH_RISK_CATEGORIES) and total_count < 50:
        delta = _rule_score("likely_business_context", -25)
        score += delta
        hits.append(RiskRuleHit("likely_business_context", delta, f"Похоже на деловой/публичный документ: {', '.join(matched_benign[:3])}."))

    if matched_benign and _business_requisites_only(categories):
        delta = _rule_score("business_requisites_only", -45)
        score += delta
        hits.append(RiskRuleHit("business_requisites_only", delta, "Похоже на легитимные реквизиты организации без профиля физлица."))

    if matched_benign and not matched_suspicious and not table_or_export:
        noisy_sensitive = _has_any(categories, ("bank_card", "snils", "inn_legal")) and not categories.get("fio")
        if noisy_sensitive:
            delta = _rule_score("likely_public_number_noise", -120)
            score += delta
            hits.append(RiskRuleHit("likely_public_number_noise", delta, "Публичный/нормативный документ с числовыми совпадениями без ФИО."))
            if not _has_any(categories, ("passport_rf", "snils", "inn_person", "mrz", "cvv")):
                delta = _rule_score("public_numeric_noise_without_person", -90)
                score += delta
                hits.append(RiskRuleHit("public_numeric_noise_without_person", delta, "Числовые совпадения без госидентификатора или профиля физлица."))

    scan_archive_context = "архив сканы" in folded_path or bool(plan and plan.metadata.get("high_ocr_context"))
    if not pii_result.has_pii and family != "video" and not embedded_document_payload:
        if not (scan_archive_context and family in {"image", "document"} and matched_suspicious):
            score = min(score, NO_PII_SCORE_CAP)

    score = max(0.0, round(score, 2))
    return RiskAssessment(
        file_path=path,
        submit_path=submit_path(path, share_root),
        score=score,
        level=_risk_level(score),
        categories=categories,
        rule_hits=hits,
        recommendation=_recommendation(score),
        document_type=_document_type(plan, categories, folded_path, embedded_document_payload),
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
        rules = "; ".join(f"{hit.rule}({hit.score_delta:+.0f})" for hit in assessment.rule_hits[:6])
        lines.append(
            f"| {assessment.score:.1f} | `{assessment.submit_path}` | {assessment.document_type} | {categories} | {rules} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_review_report(
    assessments: Iterable[RiskAssessment],
    output_path: str,
    threshold: float = DEFAULT_SUBMIT_THRESHOLD,
    review_floor: float = DEFAULT_REVIEW_FLOOR,
    limit: int = 250,
) -> None:
    assessment_list = sorted(assessments, key=lambda item: item.score, reverse=True)
    selected = [item for item in assessment_list if item.score >= threshold]
    review = [item for item in assessment_list if review_floor <= item.score < threshold]
    near_zero = [item for item in assessment_list if item.score < review_floor]

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Review report",
        "",
        f"Submit threshold: `{threshold}`",
        f"Review floor: `{review_floor}`",
        f"Selected for submit: `{len(selected)}`",
        f"Review candidates: `{len(review)}`",
        f"Low-score assessed files: `{len(near_zero)}`",
        "",
        "## Submit",
        "",
        "| score | path | type | categories | strongest rules |",
        "|---:|---|---|---|---|",
    ]

    for assessment in sorted(selected, key=lambda item: item.submit_path):
        lines.append(_review_row(assessment))

    lines.extend(
        [
            "",
            "## Review Candidates",
            "",
            "| score | path | type | categories | strongest rules |",
            "|---:|---|---|---|---|",
        ]
    )
    for assessment in review[:limit]:
        lines.append(_review_row(assessment))

    lines.extend(
        [
            "",
            "## Top Suppressed",
            "",
            "| score | path | type | categories | strongest rules |",
            "|---:|---|---|---|---|",
        ]
    )
    for assessment in near_zero[: min(50, limit)]:
        if assessment.categories or assessment.rule_hits:
            lines.append(_review_row(assessment))

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


def _fold(value: str) -> str:
    return unicodedata.normalize("NFC", value or "").casefold()


def _score_setting(mapping: Dict[str, Any], name: str, default: float) -> float:
    try:
        return float(mapping.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def _rule_score(name: str, default: float) -> float:
    return _score_setting(RULE_SCORES, name, default)


def _suspicious_path_score(name: str, default: float) -> float:
    return _score_setting(SUSPICIOUS_PATH_SCORE, name, default)


def _business_requisites_only(categories: Dict[str, int]) -> bool:
    if not categories:
        return False
    return set(categories).issubset(BUSINESS_REQUISITE_CATEGORIES)


def _looks_like_operational_contact_export(
    folded_path: str,
    categories: Dict[str, int],
    table_or_export: bool,
) -> bool:
    if not table_or_export:
        return False
    if _billing_full_dump_context(folded_path):
        return False
    if not any(keyword in folded_path for keyword in OPERATIONAL_EXPORT_PATH_KEYWORDS):
        return False
    if _has_any(categories, ("passport_rf", "snils", "inn_person", "birth_date", "bank_card", "cvv", "mrz", "identity_document")):
        return False
    return bool(categories) and set(categories).issubset(BUSINESS_CONTACT_EXPORT_CATEGORIES)


def _looks_like_mass_name_only_export(
    categories: Dict[str, int],
    table_or_export: bool,
) -> bool:
    if not table_or_export:
        return False
    if categories.get("fio", 0) < 100:
        return False
    if _has_any(categories, ("passport_rf", "snils", "inn_person", "birth_date", "bank_card", "cvv", "mrz", "identity_document", "phone", "email")):
        return False
    return set(categories).issubset(BUSINESS_CONTACT_EXPORT_CATEGORIES)


def _looks_like_legal_entity_export_without_person(
    categories: Dict[str, int],
    table_or_export: bool,
    table_hints: Counter,
    folded_path: str,
) -> bool:
    if not table_or_export or not categories:
        return False
    if _billing_full_dump_context(folded_path):
        return False
    if categories.get("fio") or table_hints.get("physical_person_rows") or table_hints.get("person_name_column"):
        return False
    if _has_any(categories, ("passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "birth_date", "bank_card", "cvv", "mrz", "identity_document")):
        return False
    return set(categories).issubset(LEGAL_ENTITY_EXPORT_CATEGORIES)


def _looks_like_physical_name_only_review(
    categories: Dict[str, int],
    table_or_export: bool,
    folded_path: str,
) -> bool:
    if not table_or_export:
        return False
    if _billing_full_dump_context(folded_path):
        return False
    if not categories.get("fio"):
        return False
    if _has_any(categories, ("passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "birth_date", "bank_card", "cvv", "mrz", "identity_document", "phone", "email")):
        return False
    return set(categories).issubset({"fio", "address"})


def _table_semantic_summary(extraction_result: Optional[Any]) -> Counter:
    counter: Counter[str] = Counter()
    if not extraction_result:
        return counter
    for block in getattr(extraction_result, "blocks", []):
        metadata = getattr(block, "metadata", {}) or {}
        counter.update(metadata.get("table_semantic_hints", {}))
        if metadata.get("physical_person_mentions"):
            counter["physical_person_rows"] += int(metadata.get("physical_person_mentions") or 0)
    return counter


def _has_high_risk_identifier(categories: Dict[str, int], weak_card_noise: bool) -> bool:
    return any(
        category in categories
        for category in HIGH_RISK_CATEGORIES
        if category != "bank_card" or not weak_card_noise
    )


def _has_profile_identifier(categories: Dict[str, int], weak_card_noise: bool) -> bool:
    if _has_any(categories, ("passport_rf", "snils", "inn_person", "birth_date", "bank_account")):
        return True
    return categories.get("bank_card", 0) > 0 and not weak_card_noise


def _has_strong_person_profile(
    categories: Dict[str, int],
    family: Optional[str],
    ocr_used: bool,
    weak_card_noise: bool,
) -> bool:
    if _has_any(categories, ("passport_rf", "snils", "inn_person", "mrz", "cvv")):
        return True
    if categories.get("identity_document", 0) and _has_any(
        categories, ("birth_date", "fio", "passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "mrz")
    ):
        return True
    if categories.get("identity_document", 0) and categories.get("fio", 0) and (family in {"image", "video"} or ocr_used):
        return True
    if categories.get("bank_card", 0) >= 3:
        return True
    if categories.get("fio", 0) and _has_profile_identifier(categories, weak_card_noise):
        return True
    return False


def _looks_like_publicish_container(folded_path: str, family: Optional[str]) -> bool:
    if family not in {"document", "web", "presentation"}:
        return False
    return "/прочее/" in folded_path or "/документы партнеров/" in folded_path or "/сайты/" in folded_path


def _misc_public_bucket_without_context(
    folded_path: str,
    family: Optional[str],
    matched_suspicious: List[str],
) -> bool:
    if matched_suspicious:
        return False
    if "/прочее/" not in folded_path and "/документы партнеров/" not in folded_path:
        return False
    return family in {"document", "web", "presentation", "structured", "spreadsheet"}


def _has_person_leak_signal(categories: Dict[str, int], folded_path: str) -> bool:
    if _has_any(
        categories,
        (
            "identity_document",
            "passport_rf",
            "passport_foreign",
            "foreign_id",
            "snils",
            "inn_person",
            "mrz",
            "cvv",
            "birth_date",
        ),
    ):
        return True
    if categories.get("fio") and _has_any(categories, ("phone", "email", "address", "bank_card", "bank_account")):
        return True
    if any(
        keyword in folded_path
        for keyword in (
            "анкет",
            "заявлен",
            "согласие",
            "паспорт",
            "passport",
            "identity",
            "личн",
            "скан",
            "scan",
            "incidents",
        )
    ):
        return True
    return False


def _has_ocr_text(extraction_result: Optional[Any]) -> bool:
    if not extraction_result:
        return False
    return any(
        getattr(block, "metadata", {}).get("ocr")
        for block in getattr(extraction_result, "blocks", [])
    )


def _has_embedded_document_payload(extraction_result: Optional[Any]) -> bool:
    if not extraction_result:
        return False
    return any(
        getattr(block, "metadata", {}).get("embedded_payload")
        and getattr(block, "metadata", {}).get("embedded_document_like")
        for block in getattr(extraction_result, "blocks", [])
    )


def _weak_single_card_noise(
    categories: Dict[str, int],
    family: Optional[str],
    table_or_export: bool,
    folded_path: str,
) -> bool:
    if categories.get("bank_card", 0) > 2:
        return False
    if not categories.get("bank_card"):
        return False
    if family == "image" and "архив сканы" in folded_path:
        return True
    if table_or_export or family not in {"document", "web"}:
        return False
    if any(keyword in folded_path for keyword in ("card", "карта", "cvv", "cvc", "bank", "банк")):
        return False
    if _has_any(categories, ("passport_rf", "snils", "inn_person", "mrz", "cvv")):
        return False
    return True


def _looks_like_table_or_export(strategy: str, family: Optional[str], extension: Optional[str]) -> bool:
    return (
        strategy in {"structured_parse", "table_parse"}
        or family in {"structured", "spreadsheet"}
        or extension in {"csv", "tsv", "json", "parquet", "xls", "xlsx"}
    )


def _billing_full_dump_context(folded_path: str) -> bool:
    return any(marker in folded_path for marker in BILLING_FULL_DUMP_CONTEXTS)


def _looks_like_public_weak_form(
    folded_path: str,
    family: Optional[str],
    categories: Dict[str, int],
    table_or_export: bool,
) -> bool:
    if "/прочее/" not in folded_path:
        return False
    if family not in {"document", "web"} or table_or_export:
        return False
    if _has_any(categories, ("passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "mrz", "cvv", "birth_date")):
        return False
    return bool(categories.get("identity_document") or _has_any(categories, ("health_data", "inn_legal", "bik", "bank_account")))


def _looks_like_public_structured_noise(
    folded_path: str,
    categories: Dict[str, int],
    table_or_export: bool,
) -> bool:
    if "/прочее/" not in folded_path or not table_or_export:
        return False
    if not any(name in folded_path for name in PUBLIC_STRUCTURED_NOISE_NAMES):
        return False
    if _has_any(categories, ("fio", "passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "mrz", "cvv", "birth_date", "address", "identity_document")):
        return False
    return True


def _looks_like_site_dump_without_profile(
    folded_path: str,
    family: Optional[str],
    categories: Dict[str, int],
    table_or_export: bool,
) -> bool:
    if not any(context in folded_path for context in SITE_DUMP_CONTEXTS):
        return False
    if family not in {"document", "web", "image", "presentation"} or table_or_export:
        return False
    if _has_any(categories, ("passport_rf", "passport_foreign", "foreign_id", "snils", "inn_person", "mrz", "cvv", "birth_date")):
        return False
    return True


def _has_unsupported_sensitive_context(extraction_result: Optional[Any], plan: Optional[ExtractionPlan]) -> bool:
    if not extraction_result or not plan:
        return False
    skipped = set(getattr(extraction_result, "skipped_steps", []))
    if not skipped.intersection({"image_prefilter", "legacy_doc_extractor", "legacy_office_extractor"}):
        return False
    path = plan.path.casefold()
    return any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS)


def _risk_level(score: float) -> str:
    if score >= RISK_LEVEL_HIGH:
        return "high"
    if score >= DEFAULT_SUBMIT_THRESHOLD:
        return "submit"
    if score >= RISK_LEVEL_REVIEW:
        return "review"
    return "low"


def _recommendation(score: float) -> str:
    if score >= RECOMMENDATION_PRIORITY:
        return "manual_review_priority"
    if score >= DEFAULT_SUBMIT_THRESHOLD:
        return "manual_review"
    return "do_not_submit_baseline"


def _document_type(
    plan: Optional[ExtractionPlan],
    categories: Dict[str, int],
    folded_path: str,
    embedded_document_payload: bool = False,
) -> str:
    if embedded_document_payload:
        return "embedded_identity_document"
    if categories.get("bank_card", 0) >= 5:
        return "card_dataset"
    if categories.get("identity_document", 0):
        return "identity_document_media"
    if categories.get("snils", 0) >= 5:
        return "identifier_list"
    if _has_any(categories, ("passport_rf", "passport_foreign", "foreign_id", "birth_date", "inn_person")) and categories.get("fio"):
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


def _review_row(assessment: RiskAssessment) -> str:
    categories = ", ".join(f"{key}:{value}" for key, value in list(assessment.categories.items())[:8])
    positive = [hit for hit in assessment.rule_hits if hit.score_delta > 0]
    negative = [hit for hit in assessment.rule_hits if hit.score_delta < 0]
    hits = positive[:4] + negative[:3]
    rules = "; ".join(f"{hit.rule}({hit.score_delta:+.0f})" for hit in hits)
    return f"| {assessment.score:.1f} | `{assessment.submit_path}` | {assessment.document_type} | {categories} | {rules} |"
