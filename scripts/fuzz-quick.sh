#!/bin/sh
# Runs every Fuzz target in the repository for FUZZTIME (default 10s) each.
#
# Fuzz packages are discovered, not listed: every directory with a
# *_test.go file (tracked or untracked, not git-ignored) declaring
# "func Fuzz...". Each Go module (the root and the adapters) is handled from
# its own directory. The run fails loudly when nothing is found, when
# "go test -list" fails, or when it lists no target for a package whose
# sources declare one.
set -eu

GO=${GO:-go}
FUZZTIME=${FUZZTIME:-10s}
cd "$(git rev-parse --show-toplevel)"

# Module directories, relative to the root: "." and every nested go.mod.
modules=$(git ls-files --cached --others --exclude-standard 'go.mod' '*/go.mod' | xargs -n1 dirname | sort -u)

# module_of prints the module directory that owns file f (the longest
# module path that is a prefix of f).
module_of() {
	best=.
	for m in $modules; do
		[ "$m" = . ] && continue
		case "$1" in
		"$m"/*) [ ${#m} -gt ${#best} ] && best=$m ;;
		esac
	done
	echo "$best"
}

# "module package" pairs, one per directory declaring a Fuzz function.
pairs=$(git ls-files --cached --others --exclude-standard '*_test.go' | while read -r f; do
	if grep -q '^func Fuzz' "$f"; then
		m=$(module_of "$f")
		d=$(dirname "$f")
		if [ "$m" = . ]; then
			echo ". ./$d"
		else
			echo "$m ./${d#"$m"}"
		fi
	fi
done | sed 's|/\.$||; s| \./$| .|; s|//|/|g' | sort -u)

if [ -z "$pairs" ]; then
	echo "fuzz-quick: no Fuzz targets found" >&2
	exit 1
fi

total=0
echo "$pairs" | {
	while read -r mod pkg; do
		if ! list=$(cd "$mod" && "$GO" test -list '^Fuzz' "$pkg"); then
			echo "fuzz-quick: go test -list failed for $mod $pkg" >&2
			exit 1
		fi
		targets=$(printf '%s\n' "$list" | grep '^Fuzz' || true)
		if [ -z "$targets" ]; then
			echo "fuzz-quick: $mod $pkg declares func Fuzz but go test -list found no target" >&2
			exit 1
		fi
		for t in $targets; do
			echo "== $mod $pkg $t"
			(cd "$mod" && "$GO" test -run '^$' -fuzz "^$t\$" -fuzztime "$FUZZTIME" "$pkg")
			total=$((total + 1))
		done
	done
	echo "fuzz-quick: $total targets passed"
}
