# pii_ner.py
from __future__ import annotations

import logging
from functools import lru_cache
from typing import List

from text_blocks import TextBlock
from pii_detector import MAX_EXAMPLES_PER_FINDING, PiiFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Маппинг Presidio entity_type → категории проекта
# ---------------------------------------------------------------------------

PRESIDIO_TO_PII: dict[str, str] = {
    "PERSON":            "fio",
    "LOCATION":          "address",
    "DATE_TIME":         "birth_date",
    "NRP":               "nationality",   # Nationality / Religion / Political group
    "MEDICAL_LICENSE":   "health_data",
    "IP_ADDRESS":        "other",
    # Иностранные идентификаторы, которых нет в regex-детекторе:
    "IBAN_CODE":         "bank_account",  # Европейские IBAN
    "US_SSN":            "foreign_id",   # SSN (США)
    "US_PASSPORT":       "passport_foreign",
    "UK_NHS":            "health_data",
    "SG_NRIC_FIN":       "foreign_id",
    "AU_TFN":            "foreign_id",
    # EMAIL и PHONE в Presidio тоже есть, но regex-детектор точнее — пропускаем
}

# Категории, которые уже закрывает regex с контрольными суммами.
# NER их не перезаписывает, только повышает confidence при совпадении.
REGEX_COVERED = {"email", "phone", "snils", "inn_person", "inn_legal",
                 "bank_card", "bik", "bank_account", "cvv", "passport_rf", "mrz"}

# ---------------------------------------------------------------------------
# Ленивая инициализация движка
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_analyzer():
    """
    Создаёт AnalyzerEngine с мультиязычной моделью xx_ent_wiki_sm.
    Вызывается один раз, результат кешируется на весь процесс.
    """
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "xx", "model_name": "xx_ent_wiki_sm"}],
    })
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["en", "ru", "de", "fr", "es", "it", "zh", "xx"],
    )

    # Кастомные recognizer-ы для РФ-документов, которых нет в Presidio из коробки
    _register_rf_recognizers(analyzer)

    return analyzer


def _register_rf_recognizers(analyzer) -> None:
    from presidio_analyzer import PatternRecognizer, Pattern

    snils = PatternRecognizer(
        supported_entity="SNILS_RF",
        name="SnilsRecognizer",
        supported_language="xx",
        patterns=[Pattern("СНИЛС", r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b", 0.6)],
        context=["снилс", "страховой", "пфр"],
    )
    inn = PatternRecognizer(
        supported_entity="INN_RF",
        name="InnRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("ИНН_12", r"\bинн\s*[:№]?\s*(\d{12})\b", 0.7),
            Pattern("ИНН_10", r"\bинн\s*[:№]?\s*(\d{10})\b", 0.65),
        ],
    )
    ogrn = PatternRecognizer(
        supported_entity="OGRN_RF",
        name="OgrnRecognizer",
        supported_language="xx",
        patterns=[Pattern("ОГРН", r"\bогрн\s*[:№]?\s*(\d{13,15})\b", 0.7)],
    )

    for recognizer in (snils, inn, ogrn):
        analyzer.registry.add_recognizer(recognizer)

    # Добавляем РФ-специфичные entity в маппинг
    PRESIDIO_TO_PII["SNILS_RF"] = "snils"
    PRESIDIO_TO_PII["INN_RF"]   = "inn_person"
    PRESIDIO_TO_PII["OGRN_RF"]  = "inn_legal"


# ---------------------------------------------------------------------------
# Определение языка блока
# ---------------------------------------------------------------------------

def _detect_lang(text: str) -> str:
    try:
        from langdetect import detect, LangDetectException
        lang = detect(text[:3000])
        supported = {"en", "ru", "de", "fr", "es", "it", "zh"}
        return lang if lang in supported else "xx"
    except Exception:
        return "xx"


# ---------------------------------------------------------------------------
# Основная функция — вызывается из pii_detector.py
# ---------------------------------------------------------------------------

def detect_pii_ner(block: TextBlock) -> List[PiiFinding]:
    """
    NER-детектор на базе Microsoft Presidio + spaCy xx_ent_wiki_sm.
    Поддерживает русский, английский и 40+ других языков.

    Возвращает список PiiFinding. Категории из REGEX_COVERED добавляются
    только если regex-детектор их НЕ нашёл (логика слияния в pii_detector.py).
    """
    text = block.text or ""
    if not text.strip() or len(text) < 10:
        return []

    try:
        analyzer = _get_analyzer()
    except Exception as exc:
        logger.warning("pii_ner: не удалось инициализировать Presidio: %s", exc)
        return []

    lang = _detect_lang(text)

    try:
        results = analyzer.analyze(text=text[:100_000], language=lang)
    except Exception:
        try:
            results = analyzer.analyze(text=text[:100_000], language="xx")
        except Exception as exc:
            logger.warning("pii_ner: ошибка анализа блока %s: %s", block.block_index, exc)
            return []

    # Группируем найденные сущности по категории
    groups: dict[str, list[str]] = {}
    for r in results:
        pii_cat = PRESIDIO_TO_PII.get(r.entity_type)
        if pii_cat:
            value = text[r.start:r.end].strip()
            if value:
                groups.setdefault(pii_cat, []).append(value)

    findings: List[PiiFinding] = []
    for category, values in groups.items():
        unique = list(dict.fromkeys(values))
        examples = [_mask(v, category) for v in unique[:MAX_EXAMPLES_PER_FINDING]]
        findings.append(PiiFinding(
            file_path=block.file_path,
            category=category,
            count=len(unique),
            confidence=0.80,
            block_index=block.block_index,
            page_or_sheet=block.page_or_sheet,
            extraction_method=block.extraction_method,
            examples=examples,
            detector=f"ner:presidio:{lang}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Маскировщики
# ---------------------------------------------------------------------------

def _mask(value: str, category: str) -> str:
    if category == "fio":
        parts = value.split()
        return " ".join(p[:1] + "." for p in parts if p)
    if category in ("address",):
        return value[:50] + ("…" if len(value) > 50 else "")
    if category == "birth_date":
        import re
        return re.sub(r"\d", "*", value)
    return value[:20] + ("…" if len(value) > 20 else "")