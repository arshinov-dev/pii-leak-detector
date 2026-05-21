# **PII Leak Detector** is a tool designed to identify and prevent the exposure of personally identifiable information.


## Как запустить:

```bash
python main.py <путь_к_папке>
```

## Назначение файлов

### file_search.py

Сканер принимает абсолютный путь и на отвечает за инвентаризацию файлов:
* определяет исходное расширение
* предполагаемый формат
* MIME-тип
* семейство формата
* уровень уверенности и статус определения.

> Детальное описание: [file_search](guides/file_search.md)