from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Dict, List

from pii_detector import MAX_EXAMPLES_PER_FINDING, PiiFinding
from text_blocks import TextBlock


logger = logging.getLogger(__name__)

PRESIDIO_TO_PII: Dict[str, str] = {
    "PERSON": "fio",
    "LOCATION": "address",
    "NRP": "nationality",
    "MEDICAL_LICENSE": "health_data",
    "IBAN_CODE": "bank_account",
    "US_SSN": "foreign_id",
    "US_PASSPORT": "passport_foreign",
    "UK_NHS": "health_data",
    "SG_NRIC_FIN": "foreign_id",
    "AU_TFN": "foreign_id",
    "SNILS_RF": "snils",
    "INN_RF": "inn_person",
    "OGRN_RF": "inn_legal",
}

REGEX_COVERED = {
    "email",
    "phone",
    "snils",
    "inn_person",
    "inn_legal",
    "bank_card",
    "bik",
    "bank_account",
    "cvv",
    "passport_rf",
    "mrz",
}

DATE_ENTITY_TYPES = {"DATE_TIME"}
BIRTH_DATE_CONTEXT_RE = re.compile(
    r"дата\s+рождения|родил(?:ся|ась)|birth\s+date|date\s+of\s+birth|d\.?\s*o\.?\s*b\.?",
    re.IGNORECASE,
)
ADDRESS_VALUE_RE = re.compile(
    r"\d|улиц|ул\.|просп|пр-т|переул|пер\.|дом|д\.|кв\.|корп|строен|address|street|road|avenue|apt",
    re.IGNORECASE,
)

_STATUS: Dict[str, str] = {
    "status": "not_used",
    "message": "",
}


@lru_cache(maxsize=1)
def _get_analyzer():
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "xx", "model_name": "xx_ent_wiki_sm"}],
        }
    )
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["xx"])

    recognizers = (
        PatternRecognizer(
            supported_entity="SNILS_RF",
            name="SnilsRecognizer",
            supported_language="xx",
            patterns=[Pattern("SNILS", r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b", 0.65)],
            context=["снилс", "страховой", "пфр"],
        ),
        PatternRecognizer(
            supported_entity="INN_RF",
            name="InnRecognizer",
            supported_language="xx",
            patterns=[
                Pattern("INN_12", r"\bинн\s*[:№#-]?\s*(\d{12})\b", 0.7),
                Pattern("INN_10", r"\bинн\s*[:№#-]?\s*(\d{10})\b", 0.65),
            ],
            context=["инн", "налогоплательщик"],
        ),
        PatternRecognizer(
            supported_entity="OGRN_RF",
            name="OgrnRecognizer",
            supported_language="xx",
            patterns=[Pattern("OGRN", r"\bогрн\s*[:№#-]?\s*(\d{13,15})\b", 0.7)],
            context=["огрн", "регистрационный"],
        ),
    )
    for recognizer in recognizers:
        analyzer.registry.add_recognizer(recognizer)

    return analyzer


def runtime_status() -> Dict[str, str]:
    return dict(_STATUS)


def detect_pii_ner(block: TextBlock) -> List[PiiFinding]:
    text = block.text or ""
    if len(text.strip()) < 10:
        return []
    if _STATUS["status"] == "unavailable":
        return []

    try:
        analyzer = _get_analyzer()
    except Exception as exc:
        _STATUS["status"] = "unavailable"
        _STATUS["message"] = f"Presidio/spaCy unavailable: {type(exc).__name__}: {exc}"
        logger.debug("pii_ner unavailable: %s", exc)
        return []

    try:
        results = analyzer.analyze(text=text, language="xx")
    except Exception as exc:
        _STATUS["status"] = "failed"
        _STATUS["message"] = f"Presidio analyze failed: {type(exc).__name__}: {exc}"
        logger.debug("pii_ner analyze failed: %s", exc)
        return []

    _STATUS["status"] = "ok"
    _STATUS["message"] = "Presidio/spaCy NER completed"

    groups: Dict[str, List[str]] = {}
    for result in results:
        category = PRESIDIO_TO_PII.get(result.entity_type)
        if result.entity_type in DATE_ENTITY_TYPES:
            category = "birth_date" if _birth_context_near(text, result.start, result.end) else None
        if not category:
            continue
        value = text[result.start : result.end].strip()
        if _accepted_entity(category, value):
            groups.setdefault(category, []).append(value)

    findings: List[PiiFinding] = []
    for category, values in groups.items():
        unique = list(dict.fromkeys(values))
        if not unique:
            continue
        findings.append(
            PiiFinding(
                file_path=block.file_path,
                category=category,
                count=len(unique),
                confidence=0.78,
                block_index=block.block_index,
                page_or_sheet=block.page_or_sheet,
                extraction_method=block.extraction_method,
                examples=[_mask(value, category) for value in unique[:MAX_EXAMPLES_PER_FINDING]],
                detector="ner:presidio:xx",
                metadata={"ml": True},
            )
        )
    return findings


def _birth_context_near(text: str, start: int, end: int) -> bool:
    context = text[max(0, start - 80) : min(len(text), end + 80)]
    return bool(BIRTH_DATE_CONTEXT_RE.search(context))


def _accepted_entity(category: str, value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    if category == "fio":
        parts = [part for part in re.split(r"\s+", value) if part]
        return len(parts) >= 2 and any(re.search(r"[A-Za-zА-Яа-яЁё]", part) for part in parts)
    if category == "address":
        return len(value) >= 8 and bool(ADDRESS_VALUE_RE.search(value))
    if category == "birth_date":
        return bool(re.search(r"\d", value))
    return True


def _mask(value: str, category: str) -> str:
    if category == "fio":
        parts = value.split()
        return " ".join(f"{part[:1]}." for part in parts if part)
    if category == "address":
        return value[:50] + ("..." if len(value) > 50 else "")
    if category == "birth_date":
        return re.sub(r"\d", "*", value)
    if category in {"foreign_id", "passport_foreign", "bank_account"}:
        return value[:4] + "*" * max(0, len(value) - 8) + value[-4:]
    return value[:30] + ("..." if len(value) > 30 else "")
