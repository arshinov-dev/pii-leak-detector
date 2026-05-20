import sys
import json
import csv
import io
import re
from typing import Iterator
from pathlib import Path
from collections import Counter
from typing import Dict, Any
import filetype


def process_file_before_return(filepath: str, detected: Dict[str, Any]) -> Any:
    """
    Выполняется перед каждым return.
    detected уже содержит определённый тип файла.
    """
    print(f"Обработка: {Path(filepath).name} | Тип: {detected.get('extension')}")
    return "обработано"


def detect_file_type(filepath: str) -> Dict[str, Any]:
    path = Path(filepath)
    # Базовый шаблон ответа
    info = {"status": "unknown", "method": "none", "mime": None, "extension": None, "is_binary": False}

    if not path.is_file():
        info.update({"status": "error", "message": "Файл не найден или не является файлом"})
        return info

    # Бинарные сигнатуры
    try:
        kind = filetype.guess(filepath)
        if kind:
            info.update({
                "status": "success",
                "method": "binary_magic",
                "mime": kind.mime,
                "extension": kind.extension, # тут расширение лежит
                "is_binary": True
            })
            info["process_result"] = process_file_before_return(filepath, info)
            return info
    except Exception as e:
        info.update({"status": "error", "message": f"filetype.guess: {e}"})
        return info

    # Чтение текста
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(65536)
        text = raw.decode('utf-8', errors='replace').strip()
    except Exception as e:
        info.update({"status": "error", "message": f"Ошибка чтения: {e}"})
        return info
    
    # TXT
    if not text:
        info.update({"status": "unknown", "mime": "text/plain", "extension": "txt", "is_binary": False})
        info["process_result"] = process_file_before_return(filepath, info)
        return info

    # HTML
    if re.match(r'<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]', text[:1000], re.IGNORECASE):
        info.update({"status": "success", "method": "text_heuristic", "mime": "text/html", "extension": "html", "is_binary": False})
        info["process_result"] = process_file_before_return(filepath, info)
        return info

    # JSON
    stripped = text.lstrip()
    if stripped.startswith(('{', '[')):
        try:
            json.loads(stripped[:2048] if len(stripped) > 2048 else stripped)
        except json.JSONDecodeError:
            pass
        info.update({"status": "success", "method": "text_heuristic", "mime": "application/json", "extension": "json", "is_binary": False})
        info["process_result"] = process_file_before_return(filepath, info)
        return info

    # CSV
    lines = text.split('\n')[:10]
    if len(lines) >= 2:
        try:
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(lines[0], delimiters=',;\t|')
            reader = csv.reader(io.StringIO('\n'.join(lines)), dialect)
            col_counts = [len(row) for row in reader if row]
            if col_counts and max(col_counts) == min(col_counts) and len(col_counts) > 1:
                info.update({"status": "success", "method": "text_heuristic", "mime": "text/csv", "extension": "csv", "is_binary": False})
                info["process_result"] = process_file_before_return(filepath, info)
                return info
        except csv.Error:
            pass

    # Fallback
    info.update({"status": "fallback", "method": "unknown", "mime": "text/plain", "extension": "txt", "is_binary": False})
    info["process_result"] = process_file_before_return(filepath, info)
    return info

# Сканер папки
def traverse_data_folder(folder_name: str) -> Iterator[Path]:
    """
    Рекурсивно проходит по папке и возвращает генератор путей ко всем файлам.
    Также проверяет существование папки и выводит стартовые сообщения.
    """
    if getattr(sys, 'frozen', False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).parent.resolve()
        
    target_dir = base_dir / folder_name

    if not target_dir.is_dir():
        print(f"Папка '{target_dir}' не найдена. Положите её рядом со скриптом")
        sys.exit(1)

    print(f"Сканирую: {target_dir}")
    print("Пожалуйста, подождите...\n")

    # Генератор отдаёт файлы по одному
    for file_path in target_dir.rglob('*'):
        if file_path.is_file():
            yield file_path


def count_and_report_files(file_paths: Iterator[Path]) -> None:
    """
    Принимает итератор путей, определяет типы файлов, собирает статистику 
    и выводит итоговый отчёт в консоль.
    """
    total_files = 0
    error_count = 0
    type_counter = Counter()
    errors_log = []

    for file_path in file_paths:
        total_files += 1
        # detect_file_type должна быть определена в вашем коде
        result = detect_file_type(str(file_path))

        if result["status"] == "error":
            error_count += 1
            errors_log.append(f"{file_path.name} → {result['message']}")
            type_counter["❌ ОШИБКА"] += 1
            continue

        # Формируем ключ для счётчика: РАСШИРЕНИЕ (MIME)
        ext = (result.get("extension") or "unknown").upper()
        mime = result.get("mime") or "unknown"
        key = f"{ext} ({mime})"
        type_counter[key] += 1

    # Вывод в консоль 
    print("\n" + "="*60)
    print("РЕЗУЛЬТАТ АНАЛИЗА")
    print("="*60)
    print(f"Всего файлов:      {total_files}")
    print(f"Ошибок чтения:    {error_count}")
    print(f"Уникальных типов:  {len([k for k in type_counter if k != '❌ ОШИБКА'])}")
    print("-" * 60)

    if type_counter:
        print(f"{'ТИП ФАЙЛА':<35} | {'КОЛИЧЕСТВО'}")
        print("-" * 60)
        # Сортировка по убыванию количества
        for file_type, count in type_counter.most_common():
            print(f"{file_type:<35} | {count}")
    else:
        print("Папка пуста.")

    if errors_log:
        print("\nПоследние ошибки (до 10 шт.):")
        for log in errors_log[:10]:
            print(f"  • {log}")
        if len(errors_log) > 10:
            print(f"  ... и ещё {len(errors_log) - 10} файлов не удалось прочитать")