import csv
import io
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import unquote

import filetype


SAMPLE_BYTES = 65536
TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251")
CSV_DELIMITERS = ",;\t|"


FORMAT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "csv": {"mime": "text/csv", "family": "structured", "is_binary": False},
    "tsv": {"mime": "text/tab-separated-values", "family": "structured", "is_binary": False},
    "json": {"mime": "application/json", "family": "structured", "is_binary": False},
    "parquet": {"mime": "application/vnd.apache.parquet", "family": "structured", "is_binary": True},
    "html": {"mime": "text/html", "family": "web", "is_binary": False},
    "htm": {"mime": "text/html", "family": "web", "is_binary": False},
    "txt": {"mime": "text/plain", "family": "text", "is_binary": False},
    "md": {"mime": "text/markdown", "family": "text", "is_binary": False},
    "markdown": {"mime": "text/markdown", "family": "text", "is_binary": False},
    "rtf": {"mime": "application/rtf", "family": "document", "is_binary": False},
    "pdf": {"mime": "application/pdf", "family": "document", "is_binary": True},
    "doc": {"mime": "application/msword", "family": "document", "is_binary": True},
    "docx": {
        "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "family": "document",
        "is_binary": True,
    },
    "xls": {"mime": "application/vnd.ms-excel", "family": "spreadsheet", "is_binary": True},
    "xlsx": {
        "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "family": "spreadsheet",
        "is_binary": True,
    },
    "ppt": {"mime": "application/vnd.ms-powerpoint", "family": "presentation", "is_binary": True},
    "pptx": {
        "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "family": "presentation",
        "is_binary": True,
    },
    "jpg": {"mime": "image/jpeg", "family": "image", "is_binary": True},
    "jpeg": {"mime": "image/jpeg", "family": "image", "is_binary": True},
    "png": {"mime": "image/png", "family": "image", "is_binary": True},
    "gif": {"mime": "image/gif", "family": "image", "is_binary": True},
    "webp": {"mime": "image/webp", "family": "image", "is_binary": True},
    "tif": {"mime": "image/tiff", "family": "image", "is_binary": True},
    "tiff": {"mime": "image/tiff", "family": "image", "is_binary": True},
    "mp4": {"mime": "video/mp4", "family": "video", "is_binary": True},
    "zip": {"mime": "application/zip", "family": "archive", "is_binary": True},
    "elf": {"mime": "application/x-executable", "family": "executable", "is_binary": True},
}


HTML_RE = re.compile(
    r"<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]",
    re.IGNORECASE,
)


@dataclass
class FileScanResult:
    """
    Формат вывода сканера.

    Остальные блоки пайплайна могут опираться на path, extension, family,
    confidence и status, не разбирая консольный вывод.
    """

    path: str
    name: str
    decoded_name: str
    size_bytes: int
    original_extension: Optional[str]
    status: str = "unknown"
    method: str = "none"
    mime: Optional[str] = None
    extension: Optional[str] = None
    family: Optional[str] = None
    is_binary: bool = False
    confidence: float = 0.0
    message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normal_extension(path: Path) -> Optional[str]:
    suffix = path.suffix.lower().lstrip(".")
    return suffix or None


def _format_meta(extension: Optional[str]) -> Dict[str, Any]:
    if not extension:
        return {}
    return FORMAT_REGISTRY.get(extension.lower(), {})


def _make_result(
    path: Path,
    status: str,
    method: str,
    extension: Optional[str],
    confidence: float,
    message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    mime: Optional[str] = None,
    family: Optional[str] = None,
    is_binary: Optional[bool] = None,
) -> FileScanResult:
    original_extension = _normal_extension(path)
    meta = _format_meta(extension)
    stat_size = path.stat().st_size if path.exists() and path.is_file() else 0

    return FileScanResult(
        path=str(path),
        name=path.name,
        decoded_name=unquote(path.name),
        size_bytes=stat_size,
        original_extension=original_extension,
        status=status,
        method=method,
        mime=mime or meta.get("mime"),
        extension=extension,
        family=family or meta.get("family"),
        is_binary=bool(meta.get("is_binary")) if is_binary is None else is_binary,
        confidence=confidence,
        message=message,
        details=details or {},
    )


def _read_sample(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(SAMPLE_BYTES)


def _looks_binary(raw: bytes) -> bool:
    if not raw:
        return False

    sample = raw[:4096]
    if b"\x00" in sample:
        return True

    control_chars = sum(1 for byte in sample if byte < 32 and byte not in (9, 10, 13))
    return control_chars / max(len(sample), 1) > 0.25


def _decode_text(raw: bytes) -> Tuple[str, str]:
    for encoding in TEXT_ENCODINGS:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace"), "utf-8-replace"


def _detect_known_binary(path: Path, raw: bytes) -> Optional[FileScanResult]:
    original_extension = _normal_extension(path)

    if raw.startswith(b"PAR1"):
        return _make_result(
            path,
            status="success",
            method="binary_magic",
            extension="parquet",
            confidence=1.0,
            message="Файл определен по сигнатуре Parquet.",
        )

    # Старые форматы Office хранятся в OLE Compound File.
    if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if original_extension in {"doc", "xls", "ppt"}:
            return _make_result(
                path,
                status="success",
                method="ole_magic_and_extension",
                extension=original_extension,
                confidence=0.95,
                message="Формат Office определен по OLE-сигнатуре и расширению.",
            )

        return _make_result(
            path,
            status="warning",
            method="ole_magic",
            extension=original_extension,
            confidence=0.65,
            mime="application/vnd.ms-office",
            family="document",
            is_binary=True,
            message="Обнаружен OLE-контейнер, но расширение не помогает уточнить тип.",
        )

    # OOXML - это ZIP-контейнер; filetype обычно справляется, но оставляем запасной путь.
    if raw.startswith(b"PK") and original_extension in {"docx", "xlsx", "pptx"}:
        return _make_result(
            path,
            status="success",
            method="zip_magic_and_extension",
            extension=original_extension,
            confidence=0.9,
            message="OOXML-файл определен по ZIP-сигнатуре и расширению.",
        )

    return None


def _detect_with_filetype(path: Path) -> Optional[FileScanResult]:
    try:
        kind = filetype.guess(str(path))
    except Exception as exc:
        return _make_result(
            path,
            status="error",
            method="binary_magic",
            extension=None,
            confidence=0.0,
            message=f"Ошибка filetype.guess: {exc}",
        )

    if not kind:
        return None

    extension = kind.extension.lower()
    meta = _format_meta(extension)
    return _make_result(
        path,
        status="success",
        method="filetype_magic",
        extension=extension,
        confidence=1.0,
        mime=kind.mime,
        family=meta.get("family"),
        is_binary=meta.get("is_binary", True),
        message="Файл определен по бинарной сигнатуре.",
    )


def _detect_html(path: Path, text: str, encoding: str) -> Optional[FileScanResult]:
    head = text[:4000]
    if not HTML_RE.search(head):
        return None

    return _make_result(
        path,
        status="success",
        method="html_heuristic",
        extension="html",
        confidence=0.9,
        is_binary=False,
        message="HTML определен по тегам в начале файла.",
        details={"encoding": encoding},
    )


def _detect_json(path: Path, text: str, encoding: str, sample_is_full: bool) -> Optional[FileScanResult]:
    original_extension = _normal_extension(path)
    stripped = text.lstrip("\ufeff \t\r\n")
    starts_like_json = stripped.startswith(("{", "["))

    if not starts_like_json and original_extension != "json":
        return None

    if starts_like_json and sample_is_full:
        try:
            json.loads(stripped)
        except json.JSONDecodeError as exc:
            if original_extension == "json":
                return _make_result(
                    path,
                    status="warning",
                    method="extension_json_invalid",
                    extension="json",
                    confidence=0.45,
                    is_binary=False,
                    message=f"Расширение .json есть, но JSON не прошел проверку: {exc}",
                    details={"encoding": encoding},
                )
            return None

        return _make_result(
            path,
            status="success",
            method="json_parse",
            extension="json",
            confidence=0.98,
            is_binary=False,
            message="JSON успешно разобран.",
            details={"encoding": encoding},
        )

    if starts_like_json:
        return _make_result(
            path,
            status="success",
            method="json_shape",
            extension="json",
            confidence=0.75,
            is_binary=False,
            message="Большой JSON определен по началу структуры; полная проверка не выполнялась.",
            details={"encoding": encoding},
        )

    return _make_result(
        path,
        status="warning",
        method="extension_only",
        extension="json",
        confidence=0.4,
        is_binary=False,
        message="Файл имеет расширение .json, но начало не похоже на JSON.",
        details={"encoding": encoding},
    )


def _csv_stats(text: str) -> Tuple[Optional[csv.Dialect], List[int]]:
    lines = [line for line in text.splitlines()[:25] if line.strip()]
    if len(lines) < 2:
        return None, []

    sample = "\n".join(lines)
    sniffer = csv.Sniffer()
    dialect = sniffer.sniff(sample, delimiters=CSV_DELIMITERS)
    reader = csv.reader(io.StringIO(sample), dialect)
    widths = [len(row) for row in reader if row]
    return dialect, widths


def _detect_csv(path: Path, text: str, encoding: str) -> Optional[FileScanResult]:
    original_extension = _normal_extension(path)

    try:
        dialect, widths = _csv_stats(text)
    except csv.Error:
        dialect, widths = None, []

    if dialect and widths:
        most_common_width, width_count = Counter(widths).most_common(1)[0]
        stable_width = width_count / len(widths) >= 0.8
        if most_common_width > 1 and stable_width:
            extension = "tsv" if dialect.delimiter == "\t" and original_extension == "tsv" else "csv"
            return _make_result(
                path,
                status="success",
                method="csv_sniffer",
                extension=extension,
                confidence=0.9,
                is_binary=False,
                message="Табличный текст определен по стабильной структуре колонок.",
                details={
                    "encoding": encoding,
                    "delimiter": dialect.delimiter,
                    "rows_sampled": len(widths),
                    "columns": most_common_width,
                },
            )

    if original_extension in {"csv", "tsv"}:
        return _make_result(
            path,
            status="warning",
            method="extension_only",
            extension=original_extension,
            confidence=0.45,
            is_binary=False,
            message="Расширение табличное, но структура CSV/TSV не подтверждена.",
            details={"encoding": encoding},
        )

    return None


def _detect_by_extension(path: Path, raw: bytes) -> Optional[FileScanResult]:
    original_extension = _normal_extension(path)
    if not original_extension or original_extension not in FORMAT_REGISTRY:
        return None

    status = "warning" if _looks_binary(raw) else "success"
    confidence = 0.7 if status == "success" else 0.55
    message = "Тип определен по расширению файла."
    if status == "warning":
        message = "Формат определен только по расширению; сигнатура не подтверждена."

    return _make_result(
        path,
        status=status,
        method="extension_only",
        extension=original_extension,
        confidence=confidence,
        message=message,
    )


def detect_file_type(filepath: str) -> Dict[str, Any]:
    """
    Определяет формат файла и возвращает структурированный словарь.

    Следующие этапы пайплайна будут работать с этими полями напрямую, без парсинга консоли.
    """
    path = Path(filepath)

    if not path.is_file():
        return _make_result(
            path,
            status="error",
            method="none",
            extension=None,
            confidence=0.0,
            message="Файл не найден или не является обычным файлом.",
        ).to_dict()

    try:
        raw = _read_sample(path)
    except Exception as exc:
        return _make_result(
            path,
            status="error",
            method="read",
            extension=None,
            confidence=0.0,
            message=f"Ошибка чтения: {exc}",
        ).to_dict()

    binary_result = _detect_known_binary(path, raw)
    if binary_result:
        return binary_result.to_dict()

    filetype_result = _detect_with_filetype(path)
    if filetype_result:
        return filetype_result.to_dict()

    if not raw:
        return _make_result(
            path,
            status="unknown",
            method="empty_file",
            extension=_normal_extension(path) or "txt",
            confidence=0.3,
            message="Файл пустой.",
        ).to_dict()

    if _looks_binary(raw):
        extension_result = _detect_by_extension(path, raw)
        if extension_result:
            return extension_result.to_dict()

        return _make_result(
            path,
            status="unknown",
            method="binary_unknown",
            extension=_normal_extension(path),
            confidence=0.2,
            is_binary=True,
            message="Файл выглядит бинарным, но формат не распознан.",
        ).to_dict()

    text, encoding = _decode_text(raw)
    sample_is_full = path.stat().st_size <= len(raw)

    for detector in (
        lambda: _detect_html(path, text, encoding),
        lambda: _detect_json(path, text, encoding, sample_is_full),
        lambda: _detect_csv(path, text, encoding),
    ):
        result = detector()
        if result:
            return result.to_dict()

    extension_result = _detect_by_extension(path, raw)
    if extension_result:
        return extension_result.to_dict()

    return _make_result(
        path,
        status="unknown",
        method="text_fallback",
        extension="txt",
        confidence=0.4,
        is_binary=False,
        message="Файл читается как текст, но точный формат не определен.",
        details={"encoding": encoding},
    ).to_dict()


def resolve_scan_root(folder_name: str) -> Path:
    """
    Определяет корневую папку сканирования.

    Поддерживаются абсолютные пути, пути относительно текущей директории
    запуска и старое поведение: папка рядом со скриптом.
    """
    candidate = Path(folder_name).expanduser()

    if candidate.is_absolute():
        if candidate.is_dir():
            return candidate.resolve()
        raise FileNotFoundError(f"Папка '{candidate}' не найдена.")

    cwd_candidate = (Path.cwd() / candidate).resolve()
    if cwd_candidate.is_dir():
        return cwd_candidate

    script_candidate = (Path(__file__).parent.resolve() / candidate).resolve()
    if script_candidate.is_dir():
        return script_candidate

    raise FileNotFoundError(
        f"Папка '{folder_name}' не найдена ни относительно текущей директории, ни рядом со скриптом."
    )


def traverse_data_folder(folder_name: str, verbose: bool = True) -> Iterator[Path]:
    """
    Рекурсивно проходит по папке и возвращает пути ко всем обычным файлам.
    """
    target_dir = resolve_scan_root(folder_name)

    if verbose:
        print(f"Сканирую: {target_dir}")
        print("Пожалуйста, подождите...\n")

    for file_path in target_dir.rglob("*"):
        if file_path.is_file():
            yield file_path


def scan_files(file_paths: Iterable[Path]) -> Iterator[Dict[str, Any]]:
    """
    Лениво сканирует поток путей и возвращает структурированные результаты.
    """
    for file_path in file_paths:
        yield detect_file_type(str(file_path))


def _format_counter_key(result: Dict[str, Any]) -> str:
    extension = (result.get("extension") or "unknown").upper()
    mime = result.get("mime") or "unknown"
    return f"{extension} ({mime})"


def count_and_report_files(file_paths: Iterable[Path]) -> List[Dict[str, Any]]:
    """
    Сканирует файлы, печатает краткий отчет и возвращает полный инвентарь.
    """
    results = list(scan_files(file_paths))

    type_counter = Counter()
    status_counter = Counter()
    errors_log: List[str] = []
    warnings_log: List[str] = []

    for result in results:
        status = result.get("status") or "unknown"
        status_counter[status] += 1

        if status == "error":
            errors_log.append(f"{result.get('name')} -> {result.get('message')}")
            continue

        if status in {"warning", "unknown"}:
            warnings_log.append(f"{result.get('name')} -> {result.get('message')}")

        type_counter[_format_counter_key(result)] += 1

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТ СКАНИРОВАНИЯ")
    print("=" * 60)
    print(f"Всего файлов:       {len(results)}")
    print(f"Успешно:            {status_counter.get('success', 0)}")
    print(f"Предупреждений:     {status_counter.get('warning', 0)}")
    print(f"Не распознано:      {status_counter.get('unknown', 0)}")
    print(f"Ошибок чтения:      {status_counter.get('error', 0)}")
    print(f"Уникальных типов:   {len(type_counter)}")
    print("-" * 60)

    if type_counter:
        print(f"{'ТИП ФАЙЛА':<42} | {'КОЛИЧЕСТВО'}")
        print("-" * 60)
        for file_type, count in type_counter.most_common():
            print(f"{file_type:<42} | {count}")
    else:
        print("Папка пуста.")

    if warnings_log:
        print("\nФайлы, требующие уточнения (до 10 шт.):")
        for log in warnings_log[:10]:
            print(f"  - {log}")
        if len(warnings_log) > 10:
            print(f"  ... и еще {len(warnings_log) - 10} файлов")

    if errors_log:
        print("\nОшибки чтения (до 10 шт.):")
        for log in errors_log[:10]:
            print(f"  - {log}")
        if len(errors_log) > 10:
            print(f"  ... и еще {len(errors_log) - 10} файлов")

    return results
