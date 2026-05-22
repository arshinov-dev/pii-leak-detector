import os
import re
import pandas as pd
from natasha import Segmenter, MorphVocab, NewsEmbedding, NewsNertagger, Doc

class TabularPIIDetector:
    def __init__(self):
        """Инициализация ядра детектора и лингвистических моделей Natasha"""
        self.segmenter = Segmenter()
        self.morph_vocab = MorphVocab()
        self.embedding = NewsEmbedding()
        self.ner_tagger = NewsNertagger(self.embedding)
        
        # Регулярные выражения для первичного отлова кандидатов
        self.regexes = {
            'INN': re.compile(r'\b\d{10}\b|\b\d{12}\b'),
            'SNILS': re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}\b'),
            'PASSPORT': re.compile(r'\b\d{2}\s?\d{2}\s?\d{6}\b|\b\d{4}\s?\d{6}\b'),
            'PHONE': re.compile(r'(?:\+7|8)[-\s]?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{2}\b')
        }
        
        # Маркерные слова для проверки контекста в таблице (названия колонок или соседние ячейки)
        self.context_keywords = {
            'INN': ['инн', 'налогопл', 'кпп', 'организац', 'огрн', 'контрагент', 'плательщик'],
            'SNILS': ['снилс', 'страхов', 'пенсион', 'сспс', 'физ.лицо', 'српф'],
            'PASSPORT': ['паспорт', 'пасп', 'серия', 'номер', 'выдан', 'код', 'подразд', 'уд-ние', 'личности'],
            'PHONE': ['телефон', 'тел', 'сотов', 'мобил', 'номер', 'whatsapp', 'tg', 'связи', 'контакт', 'абонент']
        }

    def _validate_inn(self, inn_str):
        """Математическая валидация ИНН по контрольным суммам (10 и 12 цифр)"""
        digits = [int(d) for d in inn_str if d.isdigit()]
        if len(digits) == 10:
            w = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            s = sum(d * w[i] for i, d in enumerate(digits[:9]))
            return (s % 11) % 10 == digits[9]
        elif len(digits) == 12:
            w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            s1 = sum(d * w1[i] for i, d in enumerate(digits[:10]))
            chk1 = (s1 % 11) % 10
            w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            s2 = sum(d * w2[i] for i, d in enumerate(digits[:11]))
            chk2 = (s2 % 11) % 10
            return chk1 == digits[10] and chk2 == digits[11]
        return False

    def _validate_snils(self, snils_str):
        """Математическая валидация СНИЛС по контрольной сумме"""
        digits = [int(d) for d in snils_str if d.isdigit()]
        if len(digits) != 11:
            return False
        num = digits[:9]
        chk_val = digits[9] * 10 + digits[10]
        total_sum = sum(d * (9 - i) for i, d in enumerate(num))
        if total_sum < 100:
            calc_chk = total_sum
        elif total_sum in (100, 101):
            calc_chk = 0
        else:
            rem = total_sum % 101
            if rem < 100:
                calc_chk = rem
            elif rem in (100, 101):
                calc_chk = 0
        return calc_chk == chk_val

    def _mask_value(self, value, pii_type):
        """Безопасное маскирование значения для отчета (не светим ПДн)"""
        val_str = str(value)
        if pii_type in ['INN', 'SNILS', 'PASSPORT'] and len(val_str) > 4:
            return f"{val_str[:3]}***{val_str[-2:]}"
        elif pii_type == 'PHONE' and len(val_str) > 5:
            return f"{val_str[:4]}***{val_str[-3:]}"
        elif pii_type == 'FIO':
            parts = val_str.split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1][0]}."  # Иванов И.
            return f"{val_str[:3]}***"
        return "***"

    def analyze_tabular_file(self, file_path):
        """
        Главная точка входа. На вход подается путь к файлу.
        На выход отдается список словарей с найденными ПДн для классификатора рисков.
        """
        if not os.path.exists(file_path):
            print(f"Ошибка: Файл {file_path} не найден.")
            return []

        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()
        
        # Словарь датафреймов: {имя_листа: dataframe}
        sheets_data = {}
        
        try:
            if ext in ['.xlsx', '.xls', '.xlsm', '.ods']:
                # Считываем ВСЕ листы сразу
                sheets_data = pd.read_excel(file_path, sheet_name=None)
            elif ext == '.csv':
                # Пытаемся считать CSV с автоопределением кодировки (дефолт utf-8, откат на cp1251)
                try:
                    sheets_data = {'StandardCSV': pd.read_csv(file_path, dtype=str)}
                except UnicodeDecodeError:
                    sheets_data = {'StandardCSV': pd.read_csv(file_path, dtype=str, encoding='cp1251')}
            else:
                print(f"Пропуск: Файл {filename} не является поддерживаемым табличным форматом.")
                return []
        except Exception as e:
            print(f"Ошибка при чтении файла {filename}: {e}")
            return []

        structured_findings = []

        # Обходим каждый лист в документе
        for sheet_name, df in sheets_data.items():
            if df.empty:
                continue
                
            # Приводим названия колонок к строкам, обрабатываем пустые имена
            df.columns = [str(col) if pd.notna(col) else f"Unnamed_{i}" for i, col in enumerate(df.columns)]
            
            # Проход по каждой колонке таблицы
            for column_name in df.columns:
                # Идем по строкам этой колонки
                for row_idx, cell_value in enumerate(df[column_name]):
                    if pd.isna(cell_value):
                        continue
                        
                    val_str = str(cell_value).strip()
                    if not val_str or val_str.lower() in ['nan', 'none', 'null', '-']:
                        continue
                    
                    # 1. Формируем контекстное окружение ячейки (вся её строка + имя колонки)
                    row_series = df.iloc[row_idx]
                    all_row_values = row_series.dropna().astype(str).tolist()
                    
                    # Склеенный текстовый контекст для проверки маркерных слов
                    table_context_string = f"Колонка: {column_name} | Строка: {' | '.join(all_row_values)}".lower()
                    # Компактное окружение для передачи в классификатор рисков (первые 5 значимых ячеек)
                    row_surroundings = " | ".join(all_row_values[:5])
                    
                    # 2. Проверка РЕГУЛЯРКАМИ + математическими ЧЕК-СУММАМИ
                    for pii_type, regex in self.regexes.items():
                        for match in regex.finditer(val_str):
                            matched_val = match.group()
                            is_valid = False
                            confidence = 0.0
                            
                            if pii_type == 'INN':
                                is_valid = self._validate_inn(matched_val)
                                confidence = 1.0 if is_valid else 0.0
                            elif pii_type == 'SNILS':
                                is_valid = self._validate_snils(matched_val)
                                confidence = 1.0 if is_valid else 0.0
                            elif pii_type in ['PASSPORT', 'PHONE']:
                                # У паспортов и телефонов нет чек-сумм, они валидируются строго по контексту строки
                                has_ctx = any(kw in table_context_string for kw in self.context_keywords[pii_type])
                                is_valid = has_ctx
                                confidence = 0.95 if pii_type == 'PASSPORT' else 0.85
                            
                            # Мягкая эскалация для ИНН/СНИЛС (если чек-сумма не сошлась, но колонка называется "ИНН")
                            if pii_type in ['INN', 'SNILS'] and not is_valid:
                                if any(kw in table_context_string for kw in self.context_keywords[pii_type]):
                                    is_valid = True
                                    confidence = 0.65 # Сниженный порог уверенности (например, синтетика или опечатка)
                                    
                            if is_valid:
                                structured_findings.append({
                                    'file_name': filename,
                                    'file_path': file_path,
                                    'sheet_name': sheet_name if ext != '.csv' else None,
                                    'column_name': column_name,
                                    'row_index': row_idx,
                                    'pii_type': pii_type,
                                    'pii_value_masked': self._mask_value(matched_val, pii_type),
                                    'confidence': confidence,
                                    'row_surroundings': row_surroundings
                                })

                    # 3. Проверка текстовых ячеек через NLP-модель Natasha (ФИО и Адреса)
                    # Фильтруем слишком длинные тексты (чтобы не тормозить на бинарниках или больших параграфах)
                    if len(val_str) < 300 and not val_str.isdigit():
                        doc = Doc(val_str)
                        doc.segment(self.segmenter)
                        doc.tag_ner(self.ner_tagger)
                        
                        for span in doc.spans:
                            if span.type in ['PER', 'LOC']:
                                pii_type = 'FIO' if span.type == 'PER' else 'ADDRESS'
                                # Дополнительный микро-челлендж: если колонка называется "ID" или "Дата", отсекаем ложные шумы
                                if any(bad_kw in column_name.lower() for bad_kw in ['дата', 'date', 'id', 'номер', 'индекс']):
                                    continue
                                    
                                structured_findings.append({
                                    'file_name': filename,
                                    'file_path': file_path,
                                    'sheet_name': sheet_name if ext != '.csv' else None,
                                    'column_name': column_name,
                                    'row_index': row_idx,
                                    'pii_type': pii_type,
                                    'pii_value_masked': self._mask_value(span.text, pii_type),
                                    'confidence': 0.80 if pii_type == 'FIO' else 0.70,
                                    'row_surroundings': row_surroundings
                                })

        return structured_findings


# --- БЛОК ТЕСТИРОВАНИЯ И ЗАПУСКА ИЗ КОНСОЛИ ---
if __name__ == "__main__":
    print("=== Подготовка тестовых файлов для проверки... ===")
    
    # 1. Создаем тестовый файл Excel локально
    mock_data = {
        'ФИО сотрудников': ['Иванов Иван Иванович', 'Петров Петр Петрович', 'Абсолютно Безопасная Строка'],
        'Идентификатор клиента': ['7714058912', '1234567890', '4501123456'], 
        # Пояснение к "Идентификатор клиента": 
        # - 7714058912 — валидный ИНН юрлица (пройдет чек-сумму).
        # - 1234567890 — случайное число (завалит чек-сумму и отсеется).
        # - 4501123456 — фейк-паспорт, определится за счет контекста слова "Идентификатор" в колонке.
        'Телефон для связи': ['+79991234567', 'нет телефона', '8 (800) 555-35-35']
    }
    
    test_excel_path = "test_hackathon_data.xlsx"
    df_mock = pd.DataFrame(mock_data)
    df_mock.to_excel(test_excel_path, index=False)
    print(f"Создан демонстрационный файл: {test_excel_path}\n")

    # 2. Запускаем детектор
    print("=== Инициализация детектора и сканирование... ===")
    detector = TabularPIIDetector()
    
    # Вызываем целевую функцию, передав только путь до файла
    findings = detector.analyze_tabular_file(test_excel_path)
    
    # 3. Выводим результаты структурированного списка
    print(f"\n Найдено записей ПДн для передачи Вове: {len(findings)}\n")
    
    # Переводим в DataFrame просто для красивого вывода в консоль
    if findings:
        res_df = pd.DataFrame(findings)
        print(res_df[['column_name', 'row_index', 'pii_type', 'pii_value_masked', 'confidence', 'row_surroundings']].to_string())
    
    # Чистим за собой мусорный файл
    if os.path.exists(test_excel_path):
        os.remove(test_excel_path)