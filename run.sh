#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

PAT="${GH_PAT:-}"
REPO="${GH_REPO:-NSA_TAO_EQUATIONDRUGS}"
BRANCH="${BRANCH:-main}"
API=https://api.github.com
PC=https://raw.githubusercontent.com/johnbergbom/PeddleCheap/master
DS=https://raw.githubusercontent.com/francisck/DanderSpritz_docs/master

ok(){  printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
bad(){ printf '\033[31m[FAIL]\033[0m %s\n' "$*"; }
inf(){ printf '\033[36m[ .. ]\033[0m %s\n' "$*"; }
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

for t in git curl python3; do
  command -v "$t" >/dev/null || { bad "missing dependency: $t"; exit 1; }
done

hdr "fetch inputs"
mkdir -p caps bins results
for f in forward_level3_tcp_port_1163.pcap forward_level4_tcp_port_1167.pcap \
         reverse_level3_http_port_80.pcap reverse_level3_http_port_443.pcap \
         reverse_level3_tcp_port_53.pcap PeddleCheap_Lp.dll DszLpCore.exe \
         00041-pc_listen_2017_10_16_09h37m12s.966.xml; do
  [ -s "caps/$f" ] && continue
  curl -fsSL -o "caps/$f" "$PC/$f" && ok "caps/$f" || bad "caps/$f"
done
curl -fsSL -o bins/PCConfig.exe "$DS/Pc2.2/Tools/i386-winnt/PCConfig.exe" \
  && ok "bins/PCConfig.exe" || bad "bins/PCConfig.exe"

hdr "selftests"
{ python3 harness/extract.py --selftest
  python3 harness/verify.py   --selftest
  python3 harness/diffblob.py --selftest ; } 2>&1 | tee results/selftest.txt

hdr "capture probe"
for f in caps/*.pcap; do python3 harness/extract.py --probe "$f"; done 2>&1 | tee results/probe.txt

hdr "capture runner"
python3 harness/run_all.py caps 2>&1 | tee results/run_all.txt
python3 harness/run_all.py caps --json > results/run_all.json 2>/dev/null || true

hdr "binary vocabulary and xref"
for b in bins/PCConfig.exe caps/PeddleCheap_Lp.dll; do
  [ -f "$b" ] || continue
  echo "===== $b ====="
  python3 harness/dllflags.py "$b" 2>&1
  echo "----- xref -----"
  python3 harness/dllflags.py --xref "$b" 2>&1
  echo
done | tee results/dllflags.txt

hdr "flag value table and disassembly"
python3 harness/flags.py bins/PCConfig.exe 2>&1 | tee results/flags.txt || true
{
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000df00
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000c7e0
  python3 harness/dump.py caps/PeddleCheap_Lp.dll 0x1000c000
} > results/lp_dump.txt 2>&1 || true

hdr "log parser"
[ -f caps/00041-pc_listen_2017_10_16_09h37m12s.966.xml ] && \
  python3 harness/log_parse.py caps/00041-pc_listen_2017_10_16_09h37m12s.966.xml \
  > results/log_parse.txt 2>&1 && ok "log parsed" || bad "log parse"

hdr "report"
{
  echo "# parity report"
  echo
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -srm)"
  echo
  for f in selftest run_all dllflags log_parse; do
    echo "## $f"; echo '```'
    head -c 30000 "results/$f.txt" 2>/dev/null || echo "(missing)"
    echo '```'; echo
  done
} > results/REPORT.md
ok "results/REPORT.md"

if [ -z "$PAT" ]; then
  bad "GH_PAT not set, skipping publish"; exit 0
fi

hdr "publish"
resp=$(curl -sS -H "Authorization: Bearer $PAT" -H "Accept: application/vnd.github+json" "$API/user")
OWNER=$(printf '%s' "$resp" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("login",""))
except Exception: print("")' 2>/dev/null)
if [ -z "$OWNER" ]; then
  bad "PAT rejected. GitHub said:"
  printf '  %s\n' "$(printf '%s' "$resp" | head -c 300)"
  echo "  check: not expired, classic token with 'repo' scope, no trailing whitespace"
  exit 1
fi
ok "authenticated as $OWNER"

if curl -fsSL -H "Authorization: Bearer $PAT" "$API/repos/$OWNER/$REPO" >/dev/null 2>&1; then
  inf "repo $OWNER/$REPO exists"
else
  curl -fsSL -X POST -H "Authorization: Bearer $PAT" -H "Accept: application/vnd.github+json" \
    "$API/user/repos" -d "{\"name\":\"$REPO\",\"private\":false,\"auto_init\":false}" >/dev/null \
    && ok "created public repo $OWNER/$REPO" || { bad "repo creation failed"; exit 1; }
fi

[ -d .git ] || git init -q -b "$BRANCH"
git config user.name  "${GIT_NAME:-$OWNER}"
git config user.email "${GIT_EMAIL:-$OWNER@users.noreply.github.com}"
git remote remove origin 2>/dev/null || true
git remote add origin "https://$OWNER:$PAT@github.com/$OWNER/$REPO.git"
git add -A && git add -f results
git commit -q -m "results: $(date -u +%Y-%m-%dT%H:%M:%SZ)" || inf "nothing to commit"

if git push -u origin "$BRANCH" >/dev/null 2>&1; then
  ok "pushed to $OWNER/$REPO"
  echo
  echo "REPORT: https://raw.githubusercontent.com/$OWNER/$REPO/$BRANCH/results/REPORT.md"
else
  bad "push failed"
  exit 1
fi
