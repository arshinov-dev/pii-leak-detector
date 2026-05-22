# pii_ner.py
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Dict, List, Optional

from text_blocks import TextBlock
from pii_detector import MAX_EXAMPLES_PER_FINDING, PiiFinding, _context

logger = logging.getLogger(__name__)

PRESIDIO_TO_PII: Dict[str, str] = {
    "PERSON":            "fio",
    "LOCATION":          "address",
    "GPE":               "address",
    "NRP":               "nationality",    # Nationality/Religion/Political group
    "MEDICAL_CONDITION": "health_data",
    "MEDICAL_LICENSE":   "health_data",
    "US_SSN":            "foreign_id",
    "SG_NRIC_FIN":       "foreign_id",
    "AU_TFN":            "foreign_id",
    "IBAN_CODE":         "bank_account",   # европейские IBAN
    "UK_NHS":            "health_data",
    "US_PASSPORT":       "passport_foreign",
    "CRYPTO":            "other",
    "IP_ADDRESS":        "other",
    # Дополнительные кастомные entity ниже добавим динамически
}

# Категории, которые уже надёжно закрыты regex+checksum в pii_detector.py.
# Их мы не даём Presidio перезаписывать/дублировать.
NER_REGEX_COVERED = {
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

# Минимальные score по типам сущности Presidio (до контекстного усиления).
MIN_SCORE: Dict[str, float] = {
    "PERSON": 0.35,              # имена хотим ловить по максимуму
    "LOCATION": 0.30,
    "GPE": 0.30,
    "NRP": 0.40,
    "MEDICAL_CONDITION": 0.40,
    "MEDICAL_LICENSE": 0.45,
    "IBAN_CODE": 0.40,
    "US_SSN": 0.45,
    "UK_NHS": 0.40,
    "SG_NRIC_FIN": 0.45,
    "AU_TFN": 0.45,
    # остальным по умолчанию 0.45
}

# Ключевые слова для контекстного усиления
PERSON_CONTEXT_HINTS = (
    "гражданин", "гражданка",
    "клиент", "пациент", "сотрудник", "worker", "employee",
    "subscriber", "абонент", "student", "студент", "ученик",
)
ADDRESS_CONTEXT_HINTS = (
    "address", "адрес", "residence", "registration", "прописка", "регистрац",
    "place of birth", "место рождения",
)
HEALTH_CONTEXT_HINTS = (
    "diagnosis", "диагноз", "анамнез", "медицин", "health", "здоровье",
    "паспорт здоровья", "история болезни",
)
NRP_CONTEXT_HINTS = (
    "национальн", "religion", "религ", "political", "политическ", "party",
)

# spaCy NER по языкам

@lru_cache(maxsize=1)
def _get_spacy_en():
    import spacy
    return spacy.load("en_core_web_lg")


@lru_cache(maxsize=1)
def _get_spacy_ru():
    import spacy
    return spacy.load("ru_core_news_lg")


@lru_cache(maxsize=1)
def _get_spacy_xx():
    import spacy
    return spacy.load("xx_ent_wiki_sm")


def _choose_spacy_model(lang: str):
    """
    Выбирает spaCy-модель по языку.
    EN -> en_core_web_lg; RU -> ru_core_news_lg; остальное -> xx_ent_wiki_sm.
    """
    if lang == "en":
        return _get_spacy_en(), "en"
    if lang == "ru":
        return _get_spacy_ru(), "ru"
    return _get_spacy_xx(), "xx"


SPACY_TO_PII: Dict[str, str] = {
    "PER": "fio",
    "LOC": "address",
    "GPE": "address",
    "NORP": "nationality",
}


# Presidio Analyzer + кастомные recognizer-ы

@lru_cache(maxsize=1)
def _get_analyzer():
    """
    Создаёт AnalyzerEngine с кастомными recognizer-ами.
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    # NLP-движок Presidio: используем xx_ent_wiki_sm как базу;
    # для английского и русского всё равно основную NER-работу будет делать spaCy напрямую.
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "xx", "model_name": "xx_ent_wiki_sm"}],
        }
    )
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["en", "ru", "de", "fr", "es", "it", "zh", "xx"],
    )

    _register_custom_recognizers(analyzer)
    return analyzer


def _register_custom_recognizers(analyzer) -> None:
    """
    Локальный тюнинг Presidio: РФ-идентификаторы + спецкатегории.
    """
    from presidio_analyzer import PatternRecognizer, Pattern

    # СНИЛС РФ
    snils = PatternRecognizer(
        supported_entity="SNILS_RF",
        name="SnilsRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("СНИЛС", r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b", 0.6),
        ],
        context=["снилс", "страховой", "пфр"],
    )

    # ИНН РФ
    inn = PatternRecognizer(
        supported_entity="INN_RF",
        name="InnRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("ИНН_12", r"\bинн\s*[:№]?\s*(\d{12})\b", 0.7),
            Pattern("ИНН_10", r"\bинн\s*[:№]?\s*(\d{10})\b", 0.65),
        ],
        context=["инн", "налогоплательщика", "taxpayer", "tax"],
    )

    # ОГРН
    ogrn = PatternRecognizer(
        supported_entity="OGRN_RF",
        name="OgrnRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("ОГРН", r"\bогрн\s*[:№]?\s*(\d{13,15})\b", 0.7),
        ],
        context=["огрн", "регистраци", "egrul"],
    )

    # Специальные категории через ключевые слова
    health = PatternRecognizer(
        supported_entity="HEALTH_CONTEXT",
        name="HealthContextRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("HEALTH", r"diagnos\w+|диагноз\w+|анамнез\w+|болезн\w+", 0.35),
        ],
        context=["health", "здоровье", "медицин", "clinic", "hospital"],
    )

    religion = PatternRecognizer(
        supported_entity="RELIGION_CONTEXT",
        name="ReligionContextRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("RELIGION", r"религ\w+|православ\w+|католиц\w+|muslim\w+|christian\w+", 0.35),
        ],
        context=["religion", "вероисповедан", "faith"],
    )

    politics = PatternRecognizer(
        supported_entity="POLITICS_CONTEXT",
        name="PoliticsContextRecognizer",
        supported_language="xx",
        patterns=[
            Pattern("POLITICS", r"парти\w+|выбор\w+|депутат\w+|senator\w+|parliament\w+", 0.35),
        ],
        context=["political", "политическ", "party"],
    )

    for rec in (snils, inn, ogrn, health, religion, politics):
        analyzer.registry.add_recognizer(rec)

    # Добавляем их в маппинг PII
    PRESIDIO_TO_PII["SNILS_RF"] = "snils"
    PRESIDIO_TO_PII["INN_RF"] = "inn_person"
    PRESIDIO_TO_PII["OGRN_RF"] = "inn_legal"
    PRESIDIO_TO_PII["HEALTH_CONTEXT"] = "health_data"
    PRESIDIO_TO_PII["RELIGION_CONTEXT"] = "religion"
    PRESIDIO_TO_PII["POLITICS_CONTEXT"] = "political_views"


# Определение языка блока

def _detect_lang(text: str) -> str:
    try:
        from langdetect import detect
        lang = detect(text[:3000])
        supported = {"en", "ru", "de", "fr", "es", "it", "zh"}
        return lang if lang in supported else "xx"
    except Exception:
        return "xx"

# Основной NER-детектор: spaCy + Presidio

def detect_pii_ner(block: TextBlock) -> List[PiiFinding]:
    """
    Гибридный ML-детектор: spaCy (языко-зависимый NER) + Presidio.
    Работает мультиязычно, возвращает список PiiFinding (fio, address, nationality,
    health_data, religion, political_views, foreign_id и т.п.).

    Regex+checksum детекторы для числовых идентификаторов остаются в pii_detector.py.
    """
    text = block.text or ""
    if not text.strip():
        return []

    lang = _detect_lang(text)
    findings: List[PiiFinding] = []

    # 1) spaCy NER — извлекаем PER/LOC/NORP
    try:
        nlp, spacy_lang = _choose_spacy_model(lang)
        doc = nlp(text[:100_000])
        spacy_groups: Dict[str, List[str]] = {}
        for ent in doc.ents:
            pii_cat = SPACY_TO_PII.get(ent.label_)
            if not pii_cat:
                continue
            value = ent.text.strip()
            if not value:
                continue
            spacy_groups.setdefault(pii_cat, []).append(value)

        for category, values in spacy_groups.items():
            unique = list(dict.fromkeys(values))
            examples = [_mask(category, v) for v in unique[:MAX_EXAMPLES_PER_FINDING]]
            findings.append(
                PiiFinding(
                    file_path=block.file_path,
                    category=category,
                    count=len(unique),
                    confidence=0.80,
                    block_index=block.block_index,
                    page_or_sheet=block.page_or_sheet,
                    extraction_method=block.extraction_method,
                    examples=examples,
                    detector=f"ner:spacy:{spacy_lang}",
                )
            )
    except Exception as exc:
        logger.warning("pii_ner: spaCy NER failed for lang=%s: %s", lang, exc)

    # 2) Presidio — дополняем спецкатегории и foreign ID
    try:
        analyzer = _get_analyzer()
        pres_results = analyzer.analyze(text=text[:100_000], language=lang)
    except Exception:
        try:
            analyzer = _get_analyzer()
            pres_results = analyzer.analyze(text=text[:100_000], language="xx")
        except Exception as exc:
            logger.warning("pii_ner: Presidio failed for block %s: %s", block.block_index, exc)
            return findings

    groups: Dict[str, List[str]] = {}
    for r in pres_results:
        entity_type = r.entity_type
        base_threshold = MIN_SCORE.get(entity_type, 0.45)
        if r.score < base_threshold:
            continue

        pii_cat = PRESIDIO_TO_PII.get(entity_type)
        if not pii_cat:
            continue

        value = text[r.start:r.end].strip()
        if not value:
            continue

        # Контекстное усиление по ключевым словам
        ctx = _context(text, r.start, r.end, radius=40).casefold()
        boosted_score = r.score

        if entity_type in {"PERSON"} and any(h in ctx for h in PERSON_CONTEXT_HINTS):
            boosted_score += 0.07
        elif entity_type in {"LOCATION", "GPE"} and any(h in ctx for h in ADDRESS_CONTEXT_HINTS):
            boosted_score += 0.07
        elif entity_type in {"MEDICAL_CONDITION", "MEDICAL_LICENSE"} and any(
            h in ctx for h in HEALTH_CONTEXT_HINTS
        ):
            boosted_score += 0.08
        elif entity_type in {"NRP"} and any(h in ctx for h in NRP_CONTEXT_HINTS):
            boosted_score += 0.06

        if boosted_score < base_threshold:  # на всякий случай
            continue

        groups.setdefault(pii_cat, []).append(value)

    for category, values in groups.items():
        unique = list(dict.fromkeys(values))
        examples = [_mask(category, v) for v in unique[:MAX_EXAMPLES_PER_FINDING]]
        findings.append(
            PiiFinding(
                file_path=block.file_path,
                category=category,
                count=len(unique),
                confidence=0.78,
                block_index=block.block_index,
                page_or_sheet=block.page_or_sheet,
                extraction_method=block.extraction_method,
                examples=examples,
                detector=f"ner:presidio:{lang}",
            )
        )

    return findings



# Маскирование примеров

def _mask(category: str, value: str) -> str:
    if category == "fio":
        parts = [p for p in value.split() if p]
        return " ".join(p[:1] + "." for p in parts)
    if category == "address":
        return value[:60] + ("…" if len(value) > 60 else "")
    if category in {"health_data", "religion", "political_views"}:
        # показываем только ключевые слова, убирая цифры
        import re

        v = re.sub(r"\d", "*", value)
        return v[:40] + ("…" if len(v) > 40 else "")
    if category == "nationality":
        return value[:40] + ("…" if len(value) > 40 else "")
    if category in {"foreign_id", "bank_account"}:
        import re

        digits = re.sub(r"\D", "", value)
        if len(digits) <= 4:
            return "*" * len(digits)
        return "*" * max(0, len(digits) - 4) + digits[-4:]
    return value[:20] + ("…" if len(value) > 20 else "")


# Внешний контракт: этот набор категорий считается «прикрытым regex»,
# и NER не должен их перебивать.
def ner_regex_covered_categories() -> set[str]:
    return set(NER_REGEX_COVERED)