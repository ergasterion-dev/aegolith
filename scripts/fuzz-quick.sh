#!/bin/sh
# Runs every Fuzz target in the repository for FUZZTIME (default 10s) each.
#
# Fuzz packages are discovered, not listed: every directory with a
# *_test.go file (tracked or untracked, not git-ignored) declaring
# "func Fuzz...". Each Go module (the root and the adapters) is handled from
# its own directory. The run fails loudly when nothing is found, when
# "go test -list" fails, or when it lists no target for a package whose
# sources declare one.
#
# Paths may contain spaces: lists are newline-separated, a "module package"
# pair is tab-separated, and every expansion is quoted. (A path containing a
# newline or a tab is not supported.)
set -eu

GO=${GO:-go}
FUZZTIME=${FUZZTIME:-10s}
cd "$(git rev-parse --show-toplevel)"
tab=$(printf '\t')

# Module directories, relative to the root: "." and every nested go.mod.
modules=$(git ls-files --cached --others --exclude-standard 'go.mod' '*/go.mod' | while IFS= read -r f; do dirname "$f"; done | sort -u)

# module_of prints the module directory that owns file f (the longest
# module path that is a prefix of f).
module_of() {
	best=.
	while IFS= read -r m; do
		[ "$m" = . ] && continue
		case "$1" in
		"$m"/*) [ ${#m} -gt ${#best} ] && best=$m ;;
		esac
	done <<MODULES
$modules
MODULES
	printf '%s\n' "$best"
}

# "module<TAB>package" pairs, one per directory declaring a Fuzz function;
# the package is relative to its module ("." or "./dir").
pairs=$(git ls-files --cached --others --exclude-standard '*_test.go' | while IFS= read -r f; do
	if grep -q '^func Fuzz' "$f"; then
		m=$(module_of "$f")
		d=$(dirname "$f")
		if [ "$m" = . ]; then
			rel=$d
		else
			rel=${d#"$m"}
			rel=${rel#/}
			[ -n "$rel" ] || rel=.
		fi
		if [ "$rel" = . ]; then
			pkg=.
		else
			pkg=./$rel
		fi
		printf '%s\t%s\n' "$m" "$pkg"
	fi
done | sort -u)

if [ -z "$pairs" ]; then
	echo "fuzz-quick: no Fuzz targets found" >&2
	exit 1
fi

total=0
printf '%s\n' "$pairs" | {
	while IFS="$tab" read -r mod pkg; do
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
