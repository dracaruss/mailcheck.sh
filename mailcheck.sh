#!/bin/bash
d="$1"
[ -z "$d" ] && { echo "usage: ./mailcheck.sh <domain>"; exit 1; }

Y=$'\e[1;33m'   # yellow    - client name
P=$'\e[1;35m'   # purple    - check labels
C=$'\e[1;36m'   # cyan      - evidence/proof
B=$'\e[1;31m'   # bold red  - verdict/status
R=$'\e[0m'      # reset

echo "=== ${Y}${d}${R} ==="

# SPF
spf=$(dig +short TXT "$d" | grep -i spf1)
if [ -z "$spf" ]; then
  echo "${P}SPF:${R}    ${B}MISSING${R}"
  echo "        ${C}proof:${R} dig +short TXT $d | grep spf1  ->  (no output)"
else
  echo "${P}SPF:${R}    ${B}present${R}"
  echo "        ${C}proof:${R} $spf"
  case "$spf" in
    *"-all"*) echo "        policy: ${B}-all (hardfail, strong)${R}" ;;
    *"~all"*) echo "        policy: ${B}~all (softfail, WEAK)${R}" ;;
    *"?all"*) echo "        policy: ${B}?all (neutral, no protection)${R}" ;;
    *"+all"*) echo "        policy: ${B}+all (allows anyone - CRITICAL)${R}" ;;
    *)        echo "        policy: ${B}no all mechanism found${R}" ;;
  esac
fi

# DMARC
dmarc=$(dig +short TXT "_dmarc.$d" | grep -i DMARC1)
if [ -z "$dmarc" ]; then
  echo "${P}DMARC:${R}  ${B}MISSING${R}"
  echo "        ${C}proof:${R} dig +short TXT _dmarc.$d  ->  (no output)"
else
  pol=$(echo "$dmarc" | grep -oiE 'p=[a-z]+' | head -1)
  echo "${P}DMARC:${R}  ${B}present ($pol)${R}"
  echo "        ${C}proof:${R} $dmarc"
fi

# DKIM
echo "${P}DKIM:${R}   scanning selectors..."
found=0
label() {
  case "$1" in
    selector1|selector2) echo "Microsoft 365" ;;
    pm|pm-bounces)       echo "Postmark" ;;
    knowbe4)             echo "KnowBe4" ;;
    google)              echo "Google Workspace" ;;
    mandrill)            echo "Mandrill / Mailchimp" ;;
    everlytickey1|everlytickey2) echo "Everlytic" ;;
    k1)                  echo "MailChimp / generic" ;;
    s1|s2)               echo "SendGrid / generic" ;;
    dkim|mail|smtp|default) echo "generic / self-hosted" ;;
    *)                   echo "unknown" ;;
  esac
}
for sel in selector1 selector2 default google k1 s1 s2 pm pm-bounces \
           knowbe4 mandrill dkim mail smtp everlytickey1 everlytickey2; do
  rec=$(dig +short TXT ${sel}._domainkey.$d | grep -i DKIM1)
  [ -n "$rec" ] && {
    echo "        ${B}FOUND: $sel ($(label $sel))${R}"
    echo "        ${C}proof:${R} ${sel}._domainkey.$d  ->  ${rec:0:60}..."
    found=1
  }
done
[ "$found" -eq 0 ] && {
  echo "        ${B}none on common selectors (may use custom)${R}"
  echo "        ${C}proof:${R} dig +short TXT <sel>._domainkey.$d  ->  (no output on all common selectors)"
}

# DNSSEC
echo -n "${P}DNSSEC:${R} "
dnskey=$(dig +short DNSKEY "$d")
ad=$(dig +dnssec "$d" | grep -q 'flags:.* ad' && echo yes)
if [ -z "$dnskey" ]; then
  echo "${B}NOT signed (no DNSKEY)${R}"
  echo "        ${C}proof:${R} dig +short DNSKEY $d  ->  (no output)"
elif [ "$ad" = "yes" ]; then
  echo "${B}signed and validating (ad flag set)${R}"
  echo "        ${C}proof:${R} $(echo "$dnskey" | head -1 | cut -c1-50)..."
else
  echo "${B}DNSKEY present but not validating - check chain of trust${R}"
  echo "        ${C}proof:${R} DNSKEY present but no 'ad' flag in +dnssec query"
fi

# CAA
echo -n "${P}CAA:${R}    "
caa=$(dig +short CAA "$d")
if [ -z "$caa" ]; then
  echo "${B}none (any CA can issue - worth noting)${R}"
  echo "        ${C}proof:${R} dig +short CAA $d  ->  (no output)"
else
  echo "${B}$(echo "$caa" | tr '\n' ' ')${R}"
  echo "        ${C}proof:${R} $(echo "$caa" | tr '\n' ' ')"
fi

# MTA-STS + TLS-RPT
echo -n "${P}MTA-STS:${R}"
sts=$(dig +short TXT "_mta-sts.$d" | grep -i STSv1)
if [ -z "$sts" ]; then
  echo " ${B}none${R}"
  echo "        ${C}proof:${R} dig +short TXT _mta-sts.$d  ->  (no output)"
else
  echo " ${B}present${R}"
  echo "        ${C}proof:${R} $sts"
fi
echo -n "${P}TLS-RPT:${R}"
tlsrpt=$(dig +short TXT "_smtp._tls.$d" | grep -i TLSRPTv1)
if [ -z "$tlsrpt" ]; then
  echo " ${B}none${R}"
  echo "        ${C}proof:${R} dig +short TXT _smtp._tls.$d  ->  (no output)"
else
  echo " ${B}present${R}"
  echo "        ${C}proof:${R} $tlsrpt"
fi

# AXFR
echo "${P}AXFR:${R}   testing nameservers..."
for ns in $(dig +short NS "$d"); do
  axfr=$(dig +short AXFR "$d" @"$ns")
  if echo "$axfr" | grep -q SOA; then
    echo "        ${B}VULNERABLE via $ns (zone transfer allowed - FINDING)${R}"
    echo "        ${C}proof:${R} $(echo "$axfr" | wc -l) records returned, e.g. $(echo "$axfr" | head -1)"
  else
    echo "        ${B}refused by $ns (good)${R}"
    echo "        ${C}proof:${R} dig AXFR $d @$ns  ->  $(echo "$axfr" | grep -i 'transfer failed\|refused' | head -1 || echo 'no records returned')"
  fi
done