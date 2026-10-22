#!/bin/sh
set -eu

config_path=${1:?Missing Nginx config path}
api_host=${2:?Missing analytics API server name}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
snippet_path=/etc/nginx/snippets/rybbit-trusted-proxy.conf
test -f "$config_path"
backup_dir=$(mktemp -d /var/backups/rybbit-trusted-proxy.XXXXXX)
cp -a "$config_path" "$backup_dir/site.conf"
if [ -f "$snippet_path" ]; then
    cp -a "$snippet_path" "$backup_dir/snippet.conf"
fi

rollback() {
    status=$?
    if [ "$status" -ne 0 ]; then
        cp -a "$backup_dir/site.conf" "$config_path"
        if [ -f "$backup_dir/snippet.conf" ]; then
            cp -a "$backup_dir/snippet.conf" "$snippet_path"
        else
            rm -f "$snippet_path"
        fi
        nginx -t && systemctl reload nginx || true
    fi
    exit "$status"
}
trap rollback EXIT

install -m 644 "$script_dir/trusted-proxy.conf" "$snippet_path"
python3 - "$config_path" "$api_host" <<'PY'
import pathlib,re,shutil,sys
path=pathlib.Path(sys.argv[1])
host=sys.argv[2]
if not re.fullmatch(r'[A-Za-z0-9.-]+',host):
    raise SystemExit('Invalid analytics API server name')
content=path.read_text()
needle='    server_name '+host+';'
include='    include /etc/nginx/snippets/rybbit-trusted-proxy.conf;'
if content.count(needle)!=1:
    raise SystemExit('Expected exactly one analytics API server block')
if needle+'\n'+include not in content:
    content=content.replace(needle,needle+'\n'+include,1)
    temporary=path.with_name(path.name+'.trusted-proxy.pending')
    temporary.write_text(content)
    shutil.copystat(path,temporary)
    temporary.replace(path)
PY
nginx -t
systemctl reload nginx
systemctl is-active --quiet nginx
trap - EXIT
printf 'Nginx trusted-proxy configuration applied; backup: %s\n' "$backup_dir"
