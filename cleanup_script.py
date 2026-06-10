import re, os

path = r'c:\Users\akhad\Downloads\SOC_Sentinel_v2-main (2)\SOC_Sentinel_v2-main\WifiSecuritySystem.py'
content = open(path, encoding='utf-8').read()

# 1. Remove comments safely (respecting strings)
def remove_comments(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('#'):
            # It's a comment. Check if it looks like a hex color in a string (already matched by strings part)
            return ''
        else:
            return s
    # Match strings or comments
    pattern = re.compile(
        r'#.*|"(?:\\.|[^\\"])*"|\'(?:\\.|[^\\\'])*\'',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

content = remove_comments(content)

# 2. Remove emojis/non-ascii symbols (keeping Russian/Kazakh)
content = ''.join(c for c in content if ord(c) < 128 or c in 'АаБбВвГгДдЕеЁёЖжЗзИиЙйКкЛлМмНнОоПпРрСсТтУуФфХхЦцЧчШшЩщЪъЫыЬьЭэЮюЯяӘәҒғҚқҢңӨөҰұҮүҺһІі')

# 3. Clean up empty lines created by comment removal
content = re.sub(r'\n\s*\n', '\n\n', content)

open(path, 'w', encoding='utf-8').write(content)
