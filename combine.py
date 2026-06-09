import os

# Укажите расширения файлов, которые нужно объединить
extensions = ('.txt', '.py', '.md', '.json', '.csv') 
output_file = 'combined_output.txt'

with open(output_file, 'w', encoding='utf-8') as outfile:
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(extensions) and file != output_file and file != 'combine.py':
                file_path = os.path.join(root, file)
                outfile.write(f"\n\n--- START OF FILE: {file_path} ---\n\n")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                    outfile.write(infile.read())
                outfile.write(f"\n\n--- END OF FILE: {file_path} ---\n\n")

print(f"Готово! Все файлы объединены в {output_file}")