import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from text_blocks import TextBlock


MAX_EXAMPLES_PER_FINDING = 3


EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w.-]+\.[A-Za-zА-Яа-яЁё]{2,}(?![\w.-])")
PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:\+?7|8)[\s\-.(]{0,3}\d{3}[\s\-.)]{0,3}\d{3}[\s\-]{0,2}\d{2}[\s\-]{0,2}\d{2}(?![A-Za-z0-9-])"
)
SNILS_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{3})[- ]?(\d{3})[- ]?(\d{3})[- ]?(\d{2})(?![A-Za-z0-9-])")
INN_RE = re.compile(r"(?<![A-Za-z0-9-])(\d{10}|\d{12})(?![A-Za-z0-9-])")
PASSPORT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:серия\s*)?(\d{2}\s?\d{2})[\s,;:№#-]*(?:номер|№|N|No|Nº)?[\s:№#-]*(\d{6})(?![A-Za-z0-9])",
    re.IGNORECASE,
)
CARD_RE = re.compile(r"(?<![A-Za-z0-9-])(?:\d[ -]?){13,19}(?![A-Za-z0-9-])")
BIK_RE = re.compile(r"(?<!\d)(?:БИК|BIC)\s*[:№#-]?\s*(\d{9})(?!\d)", re.IGNORECASE)
BANK_ACCOUNT_RE = re.compile(
    r"(?<!\d)(?:р/?с|расч[её]тн(?:ый|ого)?\s+сч[её]т|сч[её]т)\s*[:№#-]?\s*(\d{20})(?!\d)",
    re.IGNORECASE,
)
CVV_RE = re.compile(r"(?<!\w)(?:CVV|CVC|CVV2|CVC2)\s*[:№#-]?\s*(\d{3,4})(?!\d)", re.IGNORECASE)
DOB_RE = re.compile(
    r"(?:дата\s+рождения|родил(?:ся|ась)|д\.?\s*р\.?|date\s+of\s+birth|birth\s+date)"
    r"[\s:№#-]{0,20}"
    r"((?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)\d{2}|(?:19|20)\d{2}[./-](?:0?[1-9]|1[0-2])[./-](?:0?[1-9]|[12]\d|3[01]))",
    re.IGNORECASE,
)
DOB_TRAILING_RE = re.compile(
    r"((?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)\d{2}|(?:19|20)\d{2}[./-](?:0?[1-9]|1[0-2])[./-](?:0?[1-9]|[12]\d|3[01]))"
    r"\s*(?:г\.?|года)?\s*(?:рождения|рожд\.?)",
    re.IGNORECASE,
)
MRZ_RE = re.compile(r"\b[A-Z0-9<]{25,44}\b")
FIO_CANDIDATE_RE = re.compile(
    r"(?<![А-Яа-яЁё])"
    r"([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?\s+"
    r"[А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?\s+"
    r"[А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁ][а-яё]{1,})?)"
    r"(?![А-Яа-яЁё])"
)
FORM_FIO_RE = re.compile(
    r"Фамилия\s*[:№#-]?\s*([А-ЯЁ][а-яё-]{1,})\s+"
    r"Имя\s*[:№#-]?\s*([А-ЯЁ][а-яё-]{1,})\s+"
    r"Отчество\s*[:№#-]?\s*([А-ЯЁ][а-яё-]{2,})",
    re.IGNORECASE,
)
IDENTITY_DOCUMENT_RE = re.compile(
    r"паспорт|удостоверени[ея]\s+личности|водительск(?:ое|ие)\s+удостоверени[ея]|"
    r"identification\s+card|identity\s+card|national\s+id|ob[cč]ansk[yý]\s+pr[uů]kaz|"
    r"czech\s+republic|ceska\s+republika",
    re.IGNORECASE,
)

PASSPORT_CONTEXT_RE = re.compile(r"паспорт|выдан|код\s+подразделения|удостоверени[ея]\s+личности", re.IGNORECASE)
ADDRESS_CONTEXT_RE = re.compile(
    r"\b(?:адрес[уа]?|прожива|регистрац|улица|ул\.|проспект|пр-т|переулок|пер\.|дом|д\.|квартира|кв\.|корпус|строение|город|г\.)\b",
    re.IGNORECASE,
)
ADDRESS_LINE_RE = re.compile(
    r"(?:адрес|прожива|регистрац|ул\.|улица|проспект|пр-т|дом|д\.|квартира|кв\.|г\.)[^\n]{0,180}\d[^\n]{0,80}",
    re.IGNORECASE,
)
ADDRESS_NEXT_LINE_RE = re.compile(
    r"(?:адрес(?:\s+(?:регистрации|фактического\s+проживания|проживания))?|зарегистрирован[а-яё]*\s+по\s+адрес[уа]?|прожива[^\n]{0,50})"
    r"[^\n:]*[:\n]\s*([^\n]{0,220}\d[^\n]{0,120})",
    re.IGNORECASE,
)

PATRONYMIC_ENDINGS = (
    "вич",
    "вна",
    "ич",
    "инична",
    "овна",
    "евна",
    "ична",
    "оглы",
    "кызы",
)

SPECIAL_KEYWORD_GROUPS: Dict[str, Sequence[str]] = {
    "health_data": (
        "диагноз",
        "заболев",
        "инвалид",
        "анамнез",
        "анализ крови",
        "вич",
        "справка о здоровье",
        "лечение",
        "пациент",
    ),
    "biometric_data": (
        "биометр",
        "отпечат",
        "радуж",
        "сетчатк",
        "голосов",
        "днк",
        "распознавание лица",
        "скан лица",
    ),
    "religion": (
        "вероисповед",
        "православ",
        "мусульман",
        "ислам",
        "иудаизм",
        "буддизм",
    ),
    "political_views": (
        "политические убеждения",
        "политическая партия",
        "член партии",
        "партийность",
    ),
    "nationality": (
        "национальность",
        "этническ",
        "раса",
        "расовая",
    ),
}

STEM_KEYWORDS = {
    "заболев",
    "инвалид",
    "политическ",
    "этническ",
}


@dataclass
class PiiFinding:
    """
    Aggregated PII evidence for one category inside one TextBlock.
    """

    file_path: str
    category: str
    count: int
    confidence: float
    block_index: int
    page_or_sheet: Optional[str]
    extraction_method: str
    examples: List[str] = field(default_factory=list)
    detector: str = "regex"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PiiFileResult:
    """
    PII findings aggregated by file.
    """

    file_path: str
    findings: List[PiiFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return sum(finding.count for finding in self.findings)

    @property
    def categories(self) -> Dict[str, int]:
        counter: Counter[str] = Counter()
        for finding in self.findings:
            counter[finding.category] += finding.count
        return dict(counter.most_common())

    @property
    def blocks_with_pii(self) -> int:
        return len({finding.block_index for finding in self.findings})

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "total_count": self.total_count,
            "categories": self.categories,
            "blocks_with_pii": self.blocks_with_pii,
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
        }


def detect_pii_in_block(block: TextBlock) -> List[PiiFinding]:
    """
    Detect PII evidence in a single TextBlock.
    """

    text = block.text or ""
    if not text.strip():
        return []

    detections: List[PiiFinding] = []
    detectors: Sequence[Callable[[TextBlock], Optional[PiiFinding]]] = (
        _detect_emails,
        _detect_phones,
        _detect_snils,
        _detect_inn,
        _detect_passports,
        _detect_cards,
        _detect_bik,
        _detect_bank_accounts,
        _detect_cvv,
        _detect_birth_dates,
        _detect_addresses,
        _detect_mrz,
        _detect_identity_documents,
        _detect_fio,
    )

    for detector in detectors:
        finding = detector(block)
        if finding:
            detections.append(finding)

    detections.extend(_detect_special_keywords(block))
    return detections


def scan_text_blocks(blocks: Iterable[TextBlock]) -> List[PiiFileResult]:
    """
    Scan blocks and return one result per file.
    """

    grouped: Dict[str, PiiFileResult] = {}
    for block in blocks:
        result = grouped.setdefault(block.file_path, PiiFileResult(file_path=block.file_path))
        if block.warnings:
            result.warnings.extend(block.warnings)
        result.findings.extend(detect_pii_in_block(block))

    return list(grouped.values())


def scan_extraction_results(extraction_results: Iterable[Any]) -> List[PiiFileResult]:
    """
    Scan ExtractionRunResult-like objects without importing the runner module.
    """

    results: List[PiiFileResult] = []
    for extraction_result in extraction_results:
        file_result = PiiFileResult(file_path=extraction_result.path)
        file_result.warnings.extend(getattr(extraction_result, "warnings", []))
        for block in getattr(extraction_result, "blocks", []):
            if block.warnings:
                file_result.warnings.extend(block.warnings)
            file_result.findings.extend(detect_pii_in_block(block))
        results.append(file_result)
    return results


def summarize_pii_results(results: Iterable[PiiFileResult]) -> Dict[str, Any]:
    result_list = list(results)
    files_with_pii = [result for result in result_list if result.has_pii]
    category_counter: Counter[str] = Counter()
    for result in files_with_pii:
        category_counter.update(result.categories)

    top_files = sorted(files_with_pii, key=lambda item: item.total_count, reverse=True)[:10]

    return {
        "total_files": len(result_list),
        "files_with_pii": len(files_with_pii),
        "total_findings": sum(result.total_count for result in files_with_pii),
        "categories": dict(category_counter.most_common()),
        "top_files": [
            {
                "path": result.file_path,
                "total_count": result.total_count,
                "categories": result.categories,
            }
            for result in top_files
        ],
    }


def print_pii_report(results: Iterable[PiiFileResult]) -> None:
    result_list = list(results)
    summary = summarize_pii_results(result_list)

    print("\n" + "=" * 60)
    print("ОБНАРУЖЕНИЕ ПДН")
    print("=" * 60)
    print(f"Файлов проверено:    {summary['total_files']}")
    print(f"Файлов с ПДн:        {summary['files_with_pii']}")
    print(f"Находок ПДн:         {summary['total_findings']}")

    _print_counter("Категории ПДн", summary["categories"])
    _print_top_files(summary["top_files"])


def _detect_emails(block: TextBlock) -> Optional[PiiFinding]:
    matches = [match.group(0) for match in EMAIL_RE.finditer(block.text)]
    return _finding(block, "email", matches, 0.95, _mask_email, "regex:email")


def _detect_phones(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in PHONE_RE.finditer(block.text):
        digits = _digits(match.group(0))
        if len(digits) == 11:
            values.append(match.group(0))
    return _finding(block, "phone", values, 0.85, _mask_digits, "regex:phone")


def _detect_snils(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in SNILS_RE.finditer(block.text):
        value = "".join(match.groups())
        if _valid_snils(value):
            values.append(value)
    return _finding(block, "snils", values, 0.98, _mask_snils, "regex+checksum:snils")


def _detect_inn(block: TextBlock) -> Optional[PiiFinding]:
    person_values = []
    legal_values = []
    for match in INN_RE.finditer(block.text):
        value = match.group(1)
        if len(value) == 12 and _valid_inn_person(value):
            person_values.append(value)
        elif len(value) == 10 and _valid_inn_legal(value):
            legal_values.append(value)

    findings = []
    person_finding = _finding(block, "inn_person", person_values, 0.96, _mask_inn, "regex+checksum:inn_person")
    legal_finding = _finding(block, "inn_legal", legal_values, 0.8, _mask_inn, "regex+checksum:inn_legal")
    if person_finding:
        findings.append(person_finding)
    if legal_finding:
        findings.append(legal_finding)
    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]

    return PiiFinding(
        file_path=block.file_path,
        category="inn",
        count=sum(item.count for item in findings),
        confidence=0.9,
        block_index=block.block_index,
        page_or_sheet=block.page_or_sheet,
        extraction_method=block.extraction_method,
        examples=[example for item in findings for example in item.examples][:MAX_EXAMPLES_PER_FINDING],
        detector="regex+checksum:inn",
        metadata={"subcategories": {item.category: item.count for item in findings}},
    )


def _detect_passports(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in PASSPORT_RE.finditer(block.text):
        context = _context(block.text, match.start(), match.end(), radius=80)
        if PASSPORT_CONTEXT_RE.search(context):
            values.append("".join(match.groups()))
    return _finding(block, "passport_rf", values, 0.9, _mask_passport, "regex+context:passport_rf")


def _detect_cards(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in CARD_RE.finditer(block.text):
        value = _digits(match.group(0))
        if 13 <= len(value) <= 19 and _valid_luhn(value) and len(set(value)) > 1:
            values.append(value)
    return _finding(block, "bank_card", values, 0.97, _mask_card, "regex+luhn:bank_card")


def _detect_bik(block: TextBlock) -> Optional[PiiFinding]:
    values = [match.group(1) for match in BIK_RE.finditer(block.text)]
    return _finding(block, "bik", values, 0.8, _mask_digits, "regex+context:bik")


def _detect_bank_accounts(block: TextBlock) -> Optional[PiiFinding]:
    values = [match.group(1) for match in BANK_ACCOUNT_RE.finditer(block.text)]
    return _finding(block, "bank_account", values, 0.85, _mask_bank_account, "regex+context:bank_account")


def _detect_cvv(block: TextBlock) -> Optional[PiiFinding]:
    values = [match.group(1) for match in CVV_RE.finditer(block.text)]
    return _finding(block, "cvv", values, 0.95, _mask_digits, "regex+context:cvv")


def _detect_birth_dates(block: TextBlock) -> Optional[PiiFinding]:
    values = [match.group(1) for match in DOB_RE.finditer(block.text)]
    values.extend(match.group(1) for match in DOB_TRAILING_RE.finditer(block.text))
    return _finding(block, "birth_date", values, 0.85, _mask_birth_date, "regex+context:birth_date")


def _detect_addresses(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in ADDRESS_LINE_RE.finditer(block.text):
        value = match.group(0).strip()
        if ADDRESS_CONTEXT_RE.search(value):
            values.append(value)
    for match in ADDRESS_NEXT_LINE_RE.finditer(block.text):
        value = match.group(1).strip()
        if ADDRESS_CONTEXT_RE.search(match.group(0)):
            values.append(value)
    return _finding(block, "address", values, 0.7, _mask_address, "regex+context:address")


def _detect_mrz(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in MRZ_RE.finditer(block.text):
        value = match.group(0)
        if "<" in value and ("RUS" in value or "P<" in value or value.count("<") >= 3):
            values.append(value)
    return _finding(block, "mrz", values, 0.92, _mask_mrz, "regex:mrz")


def _detect_identity_documents(block: TextBlock) -> Optional[PiiFinding]:
    values = [match.group(0) for match in IDENTITY_DOCUMENT_RE.finditer(block.text)]
    return _finding(
        block,
        "identity_document",
        values,
        0.75,
        lambda value: value[:40],
        "keyword:identity_document",
        deduplicate=True,
    )


def _detect_fio(block: TextBlock) -> Optional[PiiFinding]:
    values = []
    for match in FORM_FIO_RE.finditer(block.text):
        values.append(" ".join(match.groups()))
    for match in FIO_CANDIDATE_RE.finditer(block.text):
        value = match.group(1)
        words = value.split()
        if any(_looks_like_patronymic(word) for word in words) and not _looks_like_heading_context(block.text, match.start(), match.end()):
            values.append(value)
    return _finding(block, "fio", values, 0.65, _mask_fio, "regex+heuristic:fio")


def _detect_special_keywords(block: TextBlock) -> List[PiiFinding]:
    findings: List[PiiFinding] = []
    for category, keywords in SPECIAL_KEYWORD_GROUPS.items():
        matches = [keyword for keyword in keywords if _keyword_present(block.text, keyword)]
        if matches:
            findings.append(
                _finding(
                    block,
                    category,
                    matches,
                    0.6,
                    lambda value: value,
                    f"keyword:{category}",
                    deduplicate=True,
                )
            )
    return [finding for finding in findings if finding]


def _keyword_present(text: str, keyword: str) -> bool:
    pattern = r"(?<![A-Za-zА-Яа-яЁё])" + re.escape(keyword) + r"(?![A-Za-zА-Яа-яЁё])"
    if re.search(pattern, text, re.IGNORECASE):
        return True

    # Stem-like keywords intentionally omit word boundaries on the right side:
    # e.g. "заболев" should match "заболевание" and "заболеваний".
    if keyword in STEM_KEYWORDS:
        stem_pattern = r"(?<![A-Za-zА-Яа-яЁё])" + re.escape(keyword)
        return bool(re.search(stem_pattern, text, re.IGNORECASE))

    return False


def _finding(
    block: TextBlock,
    category: str,
    values: Sequence[str],
    confidence: float,
    masker: Callable[[str], str],
    detector: str,
    deduplicate: bool = False,
) -> Optional[PiiFinding]:
    if not values:
        return None

    normalized_values = list(dict.fromkeys(values)) if deduplicate else list(values)
    examples = _masked_examples(normalized_values, masker)
    return PiiFinding(
        file_path=block.file_path,
        category=category,
        count=len(normalized_values),
        confidence=confidence,
        block_index=block.block_index,
        page_or_sheet=block.page_or_sheet,
        extraction_method=block.extraction_method,
        examples=examples,
        detector=detector,
    )


def _valid_snils(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 11:
        return False
    number = int(digits[:9])
    if number <= 1_001_998:
        return False
    checksum = sum(int(digit) * weight for digit, weight in zip(digits[:9], range(9, 0, -1)))
    if checksum < 100:
        expected = checksum
    elif checksum in (100, 101):
        expected = 0
    else:
        expected = checksum % 101
        if expected == 100:
            expected = 0
    return expected == int(digits[-2:])


def _valid_inn_legal(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 10:
        return False
    coefficients = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    check = sum(int(digit) * coef for digit, coef in zip(digits[:9], coefficients)) % 11 % 10
    return check == int(digits[9])


def _valid_inn_person(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 12:
        return False
    coefficients_11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coefficients_12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    check_11 = sum(int(digit) * coef for digit, coef in zip(digits[:10], coefficients_11)) % 11 % 10
    check_12 = sum(int(digit) * coef for digit, coef in zip(digits[:11], coefficients_12)) % 11 % 10
    return check_11 == int(digits[10]) and check_12 == int(digits[11])


def _valid_luhn(value: str) -> bool:
    digits = [int(char) for char in _digits(value)]
    if not digits:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def _context(text: str, start: int, end: int, radius: int) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)]


def _masked_examples(values: Sequence[str], masker: Callable[[str], str]) -> List[str]:
    examples: List[str] = []
    seen = set()
    for value in values:
        masked = masker(value)
        if masked in seen:
            continue
        examples.append(masked)
        seen.add(masked)
        if len(examples) >= MAX_EXAMPLES_PER_FINDING:
            break
    return examples


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        masked_local = local[:1] + "*"
    else:
        masked_local = local[:1] + "***" + local[-1:]
    return f"{masked_local}@{domain}"


def _mask_digits(value: str) -> str:
    digits = _digits(value)
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * max(0, len(digits) - 4) + digits[-4:]


def _mask_snils(value: str) -> str:
    digits = _digits(value)
    return f"***-***-{digits[6:9]} {digits[9:]}" if len(digits) == 11 else _mask_digits(value)


def _mask_inn(value: str) -> str:
    digits = _digits(value)
    return digits[:2] + "*" * max(0, len(digits) - 4) + digits[-2:]


def _mask_passport(value: str) -> str:
    digits = _digits(value)
    return f"{digits[:2]} ** ******" if len(digits) >= 10 else _mask_digits(value)


def _mask_card(value: str) -> str:
    digits = _digits(value)
    return digits[:6] + "*" * max(0, len(digits) - 10) + digits[-4:] if len(digits) >= 10 else _mask_digits(value)


def _mask_bank_account(value: str) -> str:
    digits = _digits(value)
    return digits[:5] + "*" * max(0, len(digits) - 9) + digits[-4:]


def _mask_birth_date(value: str) -> str:
    return re.sub(r"\d", "*", value)


def _mask_address(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value[:70] + ("..." if len(value) > 70 else "")


def _mask_mrz(value: str) -> str:
    return value[:5] + "*" * max(0, len(value) - 10) + value[-5:]


def _mask_fio(value: str) -> str:
    words = value.split()
    if not words:
        return ""
    return " ".join(word[:1] + "." for word in words)


def _looks_like_patronymic(word: str) -> bool:
    folded = word.casefold().replace("-", "")
    return any(folded.endswith(ending) for ending in PATRONYMIC_ENDINGS)


def _looks_like_heading_context(text: str, start: int, end: int) -> bool:
    context = _context(text, start, end, radius=40)
    return bool(re.search(r"министерство|правительство|университет|федеральн", context, re.IGNORECASE))


def _print_counter(title: str, counter: Dict[str, int]) -> None:
    if not counter:
        return
    print("-" * 60)
    print(title)
    for key, value in counter.items():
        print(f"{key:<30} | {value}")


def _print_top_files(files: List[Dict[str, Any]]) -> None:
    if not files:
        return
    print("-" * 60)
    print("Топ файлов по количеству находок")
    for item in files:
        categories = ", ".join(f"{key}:{value}" for key, value in list(item["categories"].items())[:5])
        print(f"{_display_path(item['path']):<42} | {item['total_count']:<5} | {categories}")


def _display_path(path: str) -> str:
    parts = Path(path).parts
    if "share" in parts:
        index = parts.index("share")
        return "/" + "/".join(parts[index + 1 :])
    return Path(path).name
