import sys

import file_search as fs

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "share"

    try:
        files_stream = fs.traverse_data_folder(folder)
        fs.count_and_report_files(files_stream)
    except FileNotFoundError as exc:
        print(exc)
        raise SystemExit(1)
