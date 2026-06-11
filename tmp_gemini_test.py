import os, urllib.request, json, sys, traceback

api = os.environ.get('GEMINI_KEY') or os.environ.get('GEMINI_API_KEY') or ''
print('GEMINI_KEY present in env:', bool(api))
if not api:
    print('No GEMINI_KEY environment variable found. Aborting test.')
    sys.exit(2)

model = 'gemini-2.5-flash'
payload = json.dumps({
    'system_instruction': {'parts': [{'text': 'You are a test assistant.'}]},
    'contents': [{'role': 'user', 'parts': [{'text': 'Привет, проверка связи!'}]}],
    'generationConfig': {'maxOutputTokens': 200}
}).encode()

url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api}"
req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json', 'User-Agent': 'SOC-Sentinel/1.0'}, method='POST')

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print('HTTP status:', getattr(resp, 'status', '<no status>'))
        body = resp.read().decode(errors='ignore')
        print('Response body:\n', body)
except Exception as e:
    print('Exception during request:')
    traceback.print_exc()
    try:
        import urllib.error as _uerr
        if isinstance(e, _uerr.HTTPError):
            try:
                b = e.read().decode(errors='ignore')
            except Exception:
                b = '<no body>'
            print('HTTPError body:\n', b)
    except Exception:
        pass
    sys.exit(1)
