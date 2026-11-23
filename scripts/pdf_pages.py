import json, sys, subprocess, re
raw = subprocess.run(['pdftotext', '-enc', 'UTF-8', sys.argv[1], '-'], capture_output=True).stdout.decode('utf-8', 'ignore')
norm = lambda t: re.sub(r'[\s　（）()／/、，,：:·・\-]', '', t)
texts = [norm(t) for t in raw.split('\f')]
heads = json.loads(sys.argv[2]); out = {}
k0 = norm(heads[0]['t'])[:6]
cur = next(i for i in range(2, len(texts)) if k0 in texts[i][:30])
for h in heads:
    key = norm(h['t'])[:8]
    i = next((i for i in range(cur, len(texts)) if (key in texts[i][:30] if h['lv'] == 1 else key in texts[i])), None)
    if i is not None: out[h['id']] = i + 1; cur = i
print(json.dumps(out))
