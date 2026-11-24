#!/bin/sh
# Regenerates attacks.jsonl and legit.jsonl from source/attacks.sh.
#
# Usage (from the repository root): sh testdata/corpus/gen.sh
#
# source/attacks.sh sends every case with curl through helper functions
# (q path hdr json form xml meth, plus code and emit). This script removes those
# helper definitions, defines replacements that print one JSON line per call
# describing the exact request curl would send, and sources the rest of the
# script. Cases before the script's "L=legit" line are attacks; the helpers
# receive the kind as their first argument ($A or $L), so it is taken from there.
#
# The hand-written legitimate cases live in legit.extra.jsonl and are appended
# to legit.jsonl after the generated ones. Output is deterministic: running
# this twice produces identical files.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/source/attacks.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# line KIND CATEGORY NAME METHOD PATH CONTENT_TYPE BODY QKEY QVALUE HNAME HVALUE FORM
# prints one corpus line. PATH may carry a raw query ("?a=1&b=2"), which is
# split into pairs. QKEY/QVALUE add one decoded query pair; HNAME/HVALUE one
# header. FORM=1 means BODY is "name=content" to be encoded the way
# curl --data-urlencode does (name as is, content percent-encoded).
PY='
import json, sys, urllib.parse
kind, cat, name, method, path, ct, body, qk, qv, hk, hv, form = sys.argv[1:]
query = []
if "?" in path:
    path, raw = path.split("?", 1)
    query = [[k, v] for k, v in urllib.parse.parse_qsl(raw, keep_blank_values=True)]
if qk:
    query.append([qk, qv])
headers = {hk: hv} if hk else {}
if form == "1":
    k, _, v = body.partition("=")
    body = k + "=" + urllib.parse.quote(v, safe="")
print(json.dumps({"name": name, "category": cat, "kind": kind, "method": method, "path": path,
                  "query": query, "headers": headers, "content_type": ct, "body": body},
                 ensure_ascii=False, separators=(",", ":")))
'
line() {
	if [ "$1" = attack ]; then out="$TMP/attacks.jsonl"; else out="$TMP/legit.jsonl"; fi
	python3 -I -c "$PY" "$@" >>"$out"
}

API="/api/v1/products"
q()    { line "$1" "$2" "$3" GET "$API/search" "" "" q "$4" "" "" 0; }
path() { line "$1" "$2" "$3" GET "$4" "" "" "" "" "" "" 0; }
hdr()  { line "$1" "$2" "$3" GET "$API" "" "" "" "" "$4" "$5" 0; }
json() { line "$1" "$2" "$3" "${5:-POST}" /api/v1/cart/items application/json "$4" "" "" "" "" 0; }
form() { line "$1" "$2" "$3" POST /api/v1/auth/login application/x-www-form-urlencoded "$4" "" "" "" "" 1; }
xml()  { line "$1" "$2" "$3" POST /api/v1/import application/xml "$4" "" "" "" "" 0; }
meth() { line "$1" "$2" "$3" "$4" "$API" "" "" "" "" "" "" 0; }

# Drop the original helper definitions: json and xml continue onto a second
# line with a trailing backslash; emit spans lines up to a closing "}" line.
awk '
	inblock { if ($0 ~ /^}/) inblock = 0; next }
	cont { cont = ($0 ~ /\\$/); next }
	/^(code|emit|q|path|hdr|json|form|xml|meth)[ ]*\(\)/ {
		if ($0 ~ /\{[ ]*(#.*)?$/) inblock = 1; else cont = ($0 ~ /\\$/)
		next
	}
	{ print }
' "$SRC" >"$TMP/cases.sh"

: >"$TMP/attacks.jsonl"
: >"$TMP/legit.jsonl"
. "$TMP/cases.sh"

cat "$DIR/legit.extra.jsonl" >>"$TMP/legit.jsonl"
mv "$TMP/attacks.jsonl" "$DIR/attacks.jsonl"
mv "$TMP/legit.jsonl" "$DIR/legit.jsonl"
wc -l "$DIR/attacks.jsonl" "$DIR/legit.jsonl"
