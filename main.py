import file_search as fs

if __name__ == "__main__":
    # Можете передать имя папки как аргумент: python main.py <Имя папки>
    folder = fs.sys.argv[1] if len(fs.sys.argv) > 1 else "share"
    fs.scan_data_folder(folder)