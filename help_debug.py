import os

def find_in_files(directory, search_str):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if search_str in content:
                        print(f"Found '{search_str}' in {path}")

find_in_files("ui", "font_family")
find_in_files("ui", "letter_spacing")
