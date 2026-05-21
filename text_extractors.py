import csv
import html
import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from text_blocks import TextBlock


TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251")
MAX_TEXT_BLOCK_CHARS = 50_000
CSV_ROWS_PER_BLOCK = 250
JSON_MAX_PARSE_BYTES = 50 * 1024 * 1024
SPREADSHEET_ROWS_PER_BLOCK = 250

DOCX_TEXT_PART_RE = re.compile(
    r"^word/(document|footnotes|endnotes|comments|header\d+|footer\d+)\.xml$"
)

XML_NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}


def extract_plain_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    params = params or {}
    text, encoding = _read_text_file(Path(file_path), params.get("encodings") or TEXT_ENCODINGS)
    return _blocks_from_text(
        file_path=file_path,
        source_type="file",
        extraction_method="plain_text_extractor",
        text=text,
        metadata={"encoding": encoding},
    )


def extract_html_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    params = params or {}
    raw_text, encoding = _read_text_file(Path(file_path), params.get("encodings") or TEXT_ENCODINGS)
    parser = _VisibleTextHTMLParser(strip_scripts=params.get("strip_scripts", True))
    parser.feed(raw_text)
    parser.close()
    text = "\n".join(parser.lines())
    return _blocks_from_text(
        file_path=file_path,
        source_type="html",
        extraction_method="html_text_extractor",
        text=text,
        metadata={"encoding": encoding},
    )


def extract_csv_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    params = params or {}
    path = Path(file_path)
    encoding = _detect_encoding(path, params.get("encodings") or TEXT_ENCODINGS)
    delimiter = params.get("delimiter") or "auto"

    with path.open("r", encoding=encoding, errors="replace", newline="") as stream:
        sample = stream.read(16_384)
        stream.seek(0)
        dialect = _detect_csv_dialect(sample, delimiter)
        reader = csv.reader(stream, dialect)
        return _row_blocks(
            file_path=file_path,
            source_type="table",
            extraction_method="csv_extractor",
            rows=reader,
            rows_per_block=int(params.get("rows_per_block") or CSV_ROWS_PER_BLOCK),
            metadata={"encoding": encoding, "delimiter": dialect.delimiter},
        )


def extract_json_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    params = params or {}
    path = Path(file_path)
    size = path.stat().st_size
    if size > int(params.get("max_parse_bytes") or JSON_MAX_PARSE_BYTES):
        encoding = _detect_encoding(path, params.get("encodings") or TEXT_ENCODINGS)
        blocks = _blocks_from_text_stream(
            file_path=file_path,
            source_type="json",
            extraction_method="json_extractor",
            path=path,
            encoding=encoding,
            metadata={"encoding": encoding, "parsed": False},
        )
        for block in blocks:
            block.warnings.append("JSON слишком большой для безопасного полного парсинга; использован текстовый fallback.")
        return blocks

    text, encoding = _read_text_file(path, params.get("encodings") or TEXT_ENCODINGS)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        blocks = _blocks_from_text(
            file_path=file_path,
            source_type="json",
            extraction_method="json_extractor",
            text=text,
            metadata={"encoding": encoding, "parsed": False},
        )
        for block in blocks:
            block.warnings.append(f"JSON не разобран, использован текстовый fallback: {exc}")
        return blocks

    rows = _json_rows(data)
    return _row_blocks(
        file_path=file_path,
        source_type="json",
        extraction_method="json_extractor",
        rows=rows,
        rows_per_block=int(params.get("rows_per_block") or CSV_ROWS_PER_BLOCK),
        metadata={"encoding": encoding, "parsed": True},
    )


def extract_parquet_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        return [
            _diagnostic_block(
                file_path=file_path,
                source_type="parquet",
                extraction_method="parquet_extractor",
                warning=f"Parquet extractor requires pyarrow; dependency is unavailable: {exc}",
            )
        ]

    table = pq.read_table(file_path)
    columns = table.column_names
    rows = (
        [f"{column}: {value}" for column, value in zip(columns, record)]
        for record in zip(*(table[column].to_pylist() for column in columns))
    )
    return _row_blocks(
        file_path=file_path,
        source_type="table",
        extraction_method="parquet_extractor",
        rows=rows,
        rows_per_block=int((params or {}).get("rows_per_block") or CSV_ROWS_PER_BLOCK),
        metadata={"columns": columns},
    )


def extract_spreadsheet_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    suffix = Path(file_path).suffix.lower()
    if suffix == ".xlsx":
        return _extract_xlsx_text(file_path, params or {})

    return [
        _diagnostic_block(
            file_path=file_path,
            source_type="workbook",
            extraction_method="spreadsheet_extractor",
            warning="XLS extraction requires an additional legacy Excel reader; this basic extractor supports XLSX only.",
        )
    ]


def extract_pdf_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    try:
        import fitz  # type: ignore
    except Exception as exc:
        return [
            _diagnostic_block(
                file_path=file_path,
                source_type="pages",
                extraction_method="pdf_text_extractor",
                warning=f"PDF text extraction requires PyMuPDF; dependency is unavailable: {exc}",
            )
        ]

    blocks: List[TextBlock] = []
    doc = None
    show_errors = bool(fitz.TOOLS.mupdf_display_errors())
    show_warnings = bool(fitz.TOOLS.mupdf_display_warnings())
    fitz.TOOLS.mupdf_display_errors(False)
    fitz.TOOLS.mupdf_display_warnings(False)
    try:
        doc = fitz.open(file_path)
        for page_index in range(len(doc)):
            page = doc.load_page(page_index)
            text = normalize_text(page.get_text("text"))
            warnings: List[str] = []
            if not text:
                warnings.append("Страница не содержит цифрового текста; может потребоваться OCR.")
            blocks.append(
                TextBlock(
                    file_path=file_path,
                    source_type="pages",
                    block_index=page_index,
                    page_or_sheet=str(page_index + 1),
                    extraction_method="pdf_text_extractor",
                    text=text,
                    warnings=warnings,
                    metadata={
                        "page_number": page_index + 1,
                        "page_count": len(doc),
                        "char_count": len(text),
                    },
                )
            )
    finally:
        if doc is not None:
            doc.close()
        fitz.TOOLS.mupdf_display_errors(show_errors)
        fitz.TOOLS.mupdf_display_warnings(show_warnings)
    return blocks


def extract_docx_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    path = Path(file_path)
    blocks: List[TextBlock] = []

    try:
        with zipfile.ZipFile(path) as archive:
            part_names = sorted(name for name in archive.namelist() if DOCX_TEXT_PART_RE.match(name))
            for part_index, part_name in enumerate(part_names):
                xml_bytes = archive.read(part_name)
                text = normalize_text("\n".join(_docx_xml_lines(xml_bytes)))
                if not text:
                    continue
                blocks.append(
                    TextBlock(
                        file_path=file_path,
                        source_type="document",
                        block_index=part_index,
                        page_or_sheet=part_name,
                        extraction_method="docx_text_extractor",
                        text=text,
                        metadata={"docx_part": part_name},
                    )
                )
    except zipfile.BadZipFile as exc:
        return [
            _diagnostic_block(
                file_path=file_path,
                source_type="document",
                extraction_method="docx_text_extractor",
                warning=f"DOCX не является корректным ZIP-контейнером: {exc}",
            )
        ]

    if blocks:
        return blocks

    return [
        _diagnostic_block(
            file_path=file_path,
            source_type="document",
            extraction_method="docx_text_extractor",
            warning="DOCX не содержит извлекаемого текста; возможно, нужны embedded images/OCR.",
        )
    ]


def extract_rtf_text(file_path: str, params: Optional[Dict[str, Any]] = None) -> List[TextBlock]:
    text, encoding = _read_text_file(Path(file_path), (params or {}).get("encodings") or TEXT_ENCODINGS)
    stripped = normalize_text(_strip_rtf(text))
    return _blocks_from_text(
        file_path=file_path,
        source_type="document",
        extraction_method="rtf_text_extractor",
        text=stripped,
        metadata={"encoding": encoding},
    )


def extract_unsupported(
    file_path: str,
    extractor_name: str,
    reason: str,
    source_type: str = "file",
) -> List[TextBlock]:
    return [
        _diagnostic_block(
            file_path=file_path,
            source_type=source_type,
            extraction_method=extractor_name,
            warning=reason,
        )
    ]


def normalize_text(text: str) -> str:
    text = text or ""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = text.replace("\xad", "").replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    text = re.sub(r"[\xa0\u2002\u2003\u2009\u202f]", " ", text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    return "\n".join(lines).strip()


class _VisibleTextHTMLParser(HTMLParser):
    def __init__(self, strip_scripts: bool = True) -> None:
        super().__init__(convert_charrefs=True)
        self.strip_scripts = strip_scripts
        self._skip_depth = 0
        self._parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if self.strip_scripts and tag.lower() in {"script", "style", "noscript"}:
            self._skip_depth += 1
        if tag.lower() in {"br", "p", "div", "tr", "li", "section", "article", "header", "footer"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self.strip_scripts and tag.lower() in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
        if tag.lower() in {"p", "div", "tr", "li", "section", "article"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        value = html.unescape(data).strip()
        if value:
            self._parts.append(value)
            self._parts.append(" ")

    def lines(self) -> List[str]:
        return normalize_text("".join(self._parts)).splitlines()


def _read_text_file(path: Path, encodings: Iterable[str]) -> Tuple[str, str]:
    raw = path.read_bytes()
    for encoding in encodings:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8-replace"


def _detect_encoding(path: Path, encodings: Iterable[str]) -> str:
    with path.open("rb") as stream:
        raw = stream.read(64_000)
    for encoding in encodings:
        try:
            raw.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "utf-8"


def _detect_csv_dialect(sample: str, delimiter: str) -> csv.Dialect:
    if delimiter and delimiter != "auto":
        class ExplicitDialect(csv.excel):
            pass

        ExplicitDialect.delimiter = delimiter
        return ExplicitDialect

    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel


def _blocks_from_text(
    file_path: str,
    source_type: str,
    extraction_method: str,
    text: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> List[TextBlock]:
    normalized = normalize_text(text)
    if not normalized:
        return [
            TextBlock(
                file_path=file_path,
                source_type=source_type,
                block_index=0,
                extraction_method=extraction_method,
                text="",
                warnings=["Извлеченный текст пуст."],
                metadata=metadata or {},
            )
        ]

    chunks = list(_chunk_text(normalized, MAX_TEXT_BLOCK_CHARS))
    return [
        TextBlock(
            file_path=file_path,
            source_type=source_type,
            block_index=index,
            extraction_method=extraction_method,
            text=chunk,
            metadata=metadata or {},
        )
        for index, chunk in enumerate(chunks)
    ]


def _blocks_from_text_stream(
    file_path: str,
    source_type: str,
    extraction_method: str,
    path: Path,
    encoding: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> List[TextBlock]:
    blocks: List[TextBlock] = []
    with path.open("r", encoding=encoding, errors="replace") as stream:
        while True:
            chunk = stream.read(MAX_TEXT_BLOCK_CHARS)
            if not chunk:
                break
            blocks.append(
                TextBlock(
                    file_path=file_path,
                    source_type=source_type,
                    block_index=len(blocks),
                    extraction_method=extraction_method,
                    text=normalize_text(chunk),
                    metadata=metadata or {},
                )
            )

    return blocks or [
        TextBlock(
            file_path=file_path,
            source_type=source_type,
            block_index=0,
            extraction_method=extraction_method,
            text="",
            warnings=["Извлеченный текст пуст."],
            metadata=metadata or {},
        )
    ]


def _row_blocks(
    file_path: str,
    source_type: str,
    extraction_method: str,
    rows: Iterable[Iterable[Any]],
    rows_per_block: int,
    metadata: Optional[Dict[str, Any]] = None,
) -> List[TextBlock]:
    blocks: List[TextBlock] = []
    current_lines: List[str] = []
    row_start = 1
    row_index = 0

    for row_index, row in enumerate(rows, 1):
        line = " | ".join(normalize_text(str(cell)) for cell in row if str(cell).strip())
        if line:
            current_lines.append(line)
        if len(current_lines) >= rows_per_block:
            blocks.append(
                _row_block(file_path, source_type, extraction_method, blocks, current_lines, row_start, row_index, metadata)
            )
            current_lines = []
            row_start = row_index + 1

    if current_lines:
        blocks.append(
            _row_block(file_path, source_type, extraction_method, blocks, current_lines, row_start, row_index, metadata)
        )

    if blocks:
        return blocks

    return [
        TextBlock(
            file_path=file_path,
            source_type=source_type,
            block_index=0,
            extraction_method=extraction_method,
            text="",
            warnings=["Табличный источник не содержит извлекаемого текста."],
            metadata=metadata or {},
        )
    ]


def _row_block(
    file_path: str,
    source_type: str,
    extraction_method: str,
    existing_blocks: List[TextBlock],
    lines: List[str],
    row_start: int,
    row_end: int,
    metadata: Optional[Dict[str, Any]],
) -> TextBlock:
    block_metadata = dict(metadata or {})
    block_metadata.update({"row_start": row_start, "row_end": row_end})
    return TextBlock(
        file_path=file_path,
        source_type=source_type,
        block_index=len(existing_blocks),
        page_or_sheet=f"rows {row_start}-{row_end}",
        extraction_method=extraction_method,
        text=normalize_text("\n".join(lines)),
        metadata=block_metadata,
    )


def _json_rows(data: Any, prefix: str = "$") -> Iterator[List[str]]:
    if isinstance(data, list):
        for index, item in enumerate(data):
            if isinstance(item, dict):
                yield [f"{key}: {_scalar_preview(value)}" for key, value in item.items()]
            elif isinstance(item, list):
                yield [f"{prefix}[{index}]: {_scalar_preview(item)}"]
            else:
                yield [f"{prefix}[{index}]: {_scalar_preview(item)}"]
        return

    if isinstance(data, dict):
        scalar_fields = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                yield from _json_rows(value, f"{prefix}.{key}")
            else:
                scalar_fields.append(f"{prefix}.{key}: {_scalar_preview(value)}")
        if scalar_fields:
            yield scalar_fields
        return

    yield [f"{prefix}: {_scalar_preview(data)}"]


def _scalar_preview(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)


def _extract_xlsx_text(file_path: str, params: Dict[str, Any]) -> List[TextBlock]:
    try:
        with zipfile.ZipFile(file_path) as archive:
            shared_strings = _xlsx_shared_strings(archive)
            sheet_names = [name for name in archive.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")]
            blocks: List[TextBlock] = []
            for sheet_name in sorted(sheet_names):
                rows = _xlsx_rows(archive.read(sheet_name), shared_strings)
                sheet_blocks = _row_blocks(
                    file_path=file_path,
                    source_type="workbook",
                    extraction_method="spreadsheet_extractor",
                    rows=rows,
                    rows_per_block=int(params.get("rows_per_block") or SPREADSHEET_ROWS_PER_BLOCK),
                    metadata={"sheet_xml": sheet_name},
                )
                for block in sheet_blocks:
                    block.block_index = len(blocks)
                    block.page_or_sheet = sheet_name if not block.page_or_sheet else f"{sheet_name}: {block.page_or_sheet}"
                    blocks.append(block)
            return blocks or [
                _diagnostic_block(
                    file_path=file_path,
                    source_type="workbook",
                    extraction_method="spreadsheet_extractor",
                    warning="XLSX не содержит листов с извлекаемым текстом.",
                )
            ]
    except zipfile.BadZipFile as exc:
        return [
            _diagnostic_block(
                file_path=file_path,
                source_type="workbook",
                extraction_method="spreadsheet_extractor",
                warning=f"XLSX не является корректным ZIP-контейнером: {exc}",
            )
        ]


def _xlsx_shared_strings(archive: zipfile.ZipFile) -> List[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []

    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    values: List[str] = []
    for item in root.findall(".//s:si", XML_NS):
        parts = [node.text or "" for node in item.findall(".//s:t", XML_NS)]
        values.append(normalize_text("".join(parts)))
    return values


def _xlsx_rows(xml_bytes: bytes, shared_strings: List[str]) -> Iterator[List[str]]:
    root = ET.fromstring(xml_bytes)
    for row in root.findall(".//s:sheetData/s:row", XML_NS):
        values: List[str] = []
        for cell in row.findall("s:c", XML_NS):
            values.append(_xlsx_cell_value(cell, shared_strings))
        yield values


def _xlsx_cell_value(cell: ET.Element, shared_strings: List[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return normalize_text("".join(node.text or "" for node in cell.findall(".//s:t", XML_NS)))

    value_node = cell.find("s:v", XML_NS)
    if value_node is None or value_node.text is None:
        return ""

    value = value_node.text
    if cell_type == "s":
        try:
            return shared_strings[int(value)]
        except (ValueError, IndexError):
            return value
    return value


def _docx_xml_lines(xml_bytes: bytes) -> List[str]:
    root = ET.fromstring(xml_bytes)
    lines: List[str] = []
    for paragraph in root.findall(".//w:p", XML_NS):
        parts: List[str] = []
        for child in paragraph.iter():
            if child.tag == f"{{{XML_NS['w']}}}t" and child.text:
                parts.append(child.text)
            elif child.tag == f"{{{XML_NS['w']}}}tab":
                parts.append("\t")
            elif child.tag == f"{{{XML_NS['w']}}}br":
                parts.append("\n")
        line = normalize_text("".join(parts))
        if line:
            lines.append(line)
    return lines


def _strip_rtf(text: str) -> str:
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", text)
    text = re.sub(r"\\u(-?\d+)\??", _rtf_unicode_repl, text)
    text = re.sub(r"\\(par|line|tab)\b ?", "\n", text)
    text = re.sub(r"{\\(?:fonttbl|colortbl|stylesheet|info|pict)[^{}]*(?:{[^{}]*}[^{}]*)*}", " ", text)
    text = re.sub(r"\\[a-zA-Z]+\d* ?|\\.", " ", text)
    text = text.replace("{", " ").replace("}", " ")
    return text


def _rtf_unicode_repl(match: re.Match) -> str:
    value = int(match.group(1))
    if value < 0:
        value += 65536
    try:
        return chr(value)
    except ValueError:
        return " "


def _chunk_text(text: str, max_chars: int) -> Iterator[str]:
    if len(text) <= max_chars:
        yield text
        return

    current: List[str] = []
    current_len = 0
    for line in text.splitlines():
        line_len = len(line) + 1
        if current and current_len + line_len > max_chars:
            yield "\n".join(current)
            current = []
            current_len = 0
        current.append(line)
        current_len += line_len
    if current:
        yield "\n".join(current)


def _diagnostic_block(
    file_path: str,
    source_type: str,
    extraction_method: str,
    warning: str,
) -> TextBlock:
    return TextBlock(
        file_path=file_path,
        source_type=source_type,
        block_index=0,
        extraction_method=extraction_method,
        text="",
        warnings=[warning],
    )
