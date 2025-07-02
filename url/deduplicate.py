import os

input_path = os.path.join(os.path.dirname(__file__), '..', 'url.txt')

with open(input_path, 'r', encoding='utf-8') as f:
    urls = set(line.strip() for line in f if line.strip())

with open(input_path, 'w', encoding='utf-8') as f:
    for url in sorted(urls):
        f.write(url + '\n')

print(f"去重后的网址已直接写回 {input_path}")
