import argparse
import gzip
import json
import pathlib
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('--input-dir', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--tracking-host', required=True)
parser.add_argument('--domain', action='append', required=True)
args = parser.parse_args()
output = pathlib.Path(args.output)
count = 0
first = None
last = None
with gzip.open(str(output), 'wt', encoding='utf-8') as target:
    for path in sorted(pathlib.Path(args.input_dir).glob('access*.log*')):
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(str(path), 'rt', errors='replace') as source:
            for line in source:
                try:
                    row = json.loads(line)
                    request = row.get('request', {})
                    if request.get('host') != args.tracking_host or request.get('method') != 'POST':
                        continue
                    if urllib.parse.urlsplit(request.get('uri', '')).path != '/api/track':
                        continue
                    if not 200 <= row.get('status', 0) < 300:
                        continue
                    headers = request.get('headers', {})
                    origin = headers.get('Origin', [])
                    origin = origin[0] if isinstance(origin, list) and origin else origin
                    host = urllib.parse.urlsplit(origin or '').hostname or ''
                    if not any(host == domain or host.endswith('.' + domain) for domain in args.domain):
                        continue
                    ua = headers.get('User-Agent', [])
                    ua = ua[0] if isinstance(ua, list) and ua else ua
                    ip = request.get('remote_ip', '')
                    if not ua or not ip:
                        continue
                    end_ms = round(float(row['ts']) * 1000)
                    start_ms = round((float(row['ts']) - float(row.get('duration', 0))) * 1000)
                    target.write(json.dumps({'log_id': count, 'start_ms': start_ms, 'end_ms': end_ms,
                                             'hostname': host, 'ip': ip, 'ua': ua}, ensure_ascii=False) + '\n')
                    count += 1
                    first = min(first, start_ms) if first is not None else start_ms
                    last = max(last, end_ms) if last is not None else end_ms
                except (ValueError, TypeError, IndexError, KeyError):
                    continue
output.chmod(0o600)
print(json.dumps({'records': count, 'first_ms': first, 'last_ms': last}))
