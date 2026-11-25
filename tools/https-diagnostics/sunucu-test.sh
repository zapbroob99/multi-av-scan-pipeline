#!/usr/bin/env bash
set -eu
export LC_ALL=C TZ=UTC
umask 077
for binary in tcpdump timeout ss curl; do
    command -v "$binary" >/dev/null || { echo "Eksik komut: $binary" >&2; exit 1; }
done
elevate=()
if (( EUID != 0 )); then sudo -v; elevate=(sudo); fi
dir="$(mktemp -d "${TMPDIR:-/tmp}/masp-https-XXXXXX")"
report="$dir/masp-sunucu.log"
echo "Rapor: $report"
{
    date -u '+Baslangic UTC %FT%TZ'
    echo 'TCP 443 dinleyicileri:'
    "${elevate[@]}" ss -lntp 'sport = :443'
    echo 'Standart pilot backend /health (127.0.0.1:8000):'
    curl --disable --noproxy '*' -sS --max-time 5 -o /dev/null -w 'HTTP=%{http_code} toplam=%{time_total}s\n' http://127.0.0.1:8000/health || true
    echo 'UTC, IPv4 TCP 443 SYN / SYN-ACK / RST:'
} >"$report" 2>&1
echo "Simdi PC-Baslat.cmd dosyasini acin. Dinleme 150 saniye sonra bitecek."
status=0
"${elevate[@]}" timeout --signal=INT --kill-after=3 150 env TZ=UTC tcpdump -nn -tttt -l -i any -c 20000 \
    'ip and tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)' >>"$report" 2>&1 || status=$?
date -u '+Bitis UTC %FT%TZ' >>"$report"
if [[ $status != 0 && $status != 124 ]]; then
    echo "Dinleme hatasi ($status). Ayrinti: $report" >&2; tail -n 4 "$report" >&2; exit 1
fi
echo "Tamamlandi: $report"
