#!/bin/sh
# Refuse commits/pushes that contain deployment data (real addresses, customer prefixes,
# hostnames, license keys). The patterns live OUTSIDE the repository so that the list
# itself never leaks: $DNSJOS_SENSITIVE_PATTERNS, or ../DnsJos-private/sensitive-patterns.txt
# (one extended regex per line, # comments allowed).
#
#   check-sensitive.sh staged          staged changes (pre-commit)
#   check-sensitive.sh range A..B      every commit in the range (pre-push)
#   check-sensitive.sh all             whole history + working tree
set -eu
root=$(git rev-parse --show-toplevel)
pf=${DNSJOS_SENSITIVE_PATTERNS:-$root/../DnsJos-private/sensitive-patterns.txt}
if [ ! -r "$pf" ]; then
	echo "check-sensitive: pattern file $pf not found — refusing (set DNSJOS_SENSITIVE_PATTERNS)" >&2
	exit 1
fi
pat=$(grep -vE '^[[:space:]]*(#|$)' "$pf" | paste -sd'|' -)

hits() { grep -nIE "$pat" || true; }

case "${1:-staged}" in
staged)
	out=$(git diff --cached -U0 --no-color | grep -E '^\+' | grep -vE '^\+\+\+ ' | hits)
	;;
range)
	out=$(git log -p --no-color "$2" | grep -E '^[+-]|^commit |^Author:|^    ' | hits)
	;;
all)
	out=$( { git log --all -p --no-color; git ls-files -co --exclude-standard -z | xargs -0 cat 2>/dev/null; } | hits)
	;;
*)
	echo "usage: $0 staged | range A..B | all" >&2; exit 2
	;;
esac

if [ -n "$out" ]; then
	echo "check-sensitive: deployment data found — not allowed in this repository:" >&2
	printf '%s\n' "$out" | head -20 >&2
	exit 1
fi
