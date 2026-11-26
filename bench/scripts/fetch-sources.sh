#!/usr/bin/env bash
# Fetches the third-party test sources pinned in ../sources.json into
# ../.sources/<name>. Needs git and jq.
#
# The fetched trees are untrusted data and nothing in them is run: git works
# without the user's or the system's configuration (so no hooks, filters,
# credentials or URL rewrites), submodules are not fetched, and symbolic links
# are written as plain files. Only the two repositories named below are
# contacted, over https. Any failure leaves no source tree behind.
set -euo pipefail

die() {
	printf 'fetch-sources: %s\n' "$*" >&2
	exit 1
}

# The only sources that may be fetched, each from one repository.
names="crs gotestwaf"
repo_of() {
	case $1 in
	crs) echo github.com/coreruleset/coreruleset ;;
	gotestwaf) echo github.com/wallarm/gotestwaf ;;
	*) return 1 ;;
	esac
}

command -v git >/dev/null 2>&1 || die 'git is not installed'
command -v jq >/dev/null 2>&1 || die 'jq is not installed'

bench_dir=$(cd -P -- "$(dirname -- "$0")/.." && pwd)
manifest=$bench_dir/sources.json
dest=$bench_dir/.sources

[ ! -L "$dest" ] || die '.sources is a symbolic link'
mkdir -p -- "$dest"
# Remove earlier trees first, so that a failed run cannot leave a stale one.
for name in $names; do
	rm -rf -- "${dest:?}/$name"
done

[ -f "$manifest" ] || die 'sources.json is missing'
jq -e -s '
	length == 1 and (.[0] |
		type == "array"
		and all(.[];
			type == "object"
			and keys == ["commit", "included", "license", "name", "note", "repo"]
			and (.included | type) == "boolean"
			and all(.name, .repo, .commit, .license, .note;
				type == "string" and (test("[\u0000-\u001f]") | not))
			and (.name | test("^[a-z0-9-]+$")))
		and ([.[].name] | length == (unique | length))
		and ["crs", "gotestwaf"] - [.[].name] == [])
' "$manifest" >/dev/null || die 'sources.json is not valid'
rows=$(jq -r '.[] | [.name, .repo, .commit, .license, (.included | tostring), .note] | join("\u001f")' "$manifest")

work=$(mktemp -d "$dest/.work.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/home" "$work/template"

for var in $(compgen -e); do
	case $var in GIT_*) unset "$var" ;; esac
done
export HOME="$work/home" XDG_CONFIG_HOME="$work/home"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=https

safe_git() {
	git \
		-c core.hooksPath=/dev/null \
		-c core.fsmonitor=false \
		-c core.symlinks=false \
		-c core.autocrlf=false \
		-c core.protectHFS=true \
		-c core.protectNTFS=true \
		-c credential.helper= \
		-c protocol.allow=never \
		-c protocol.https.allow=always \
		-c http.followRedirects=false \
		-c transfer.fsckObjects=true \
		-c fetch.recurseSubmodules=false \
		-c submodule.recurse=false \
		"$@" </dev/null
}

fetched=""
summary=""
while IFS=$'\x1f' read -r name repo commit license included note; do
	if [ "$included" != true ]; then
		[ -n "$note" ] || die "$name: excluded without a reason in note"
		summary+="$name: not included: $note"$'\n'
		continue
	fi
	expected=$(repo_of "$name") || die "$name: not a source this script may fetch"
	[ "$repo" = "$expected" ] || die "$name: repo must be $expected"
	[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "$name: commit is not 40 hex digits"
	[ -n "$license" ] || die "$name: no licence recorded"

	tree=$work/$name
	safe_git init -q --template="$work/template" "$tree"
	safe_git -C "$tree" fetch -q --depth=1 --no-tags --no-recurse-submodules \
		"https://$expected.git" "$commit" || die "$name: fetching $commit failed"
	safe_git -C "$tree" checkout -q --detach FETCH_HEAD || die "$name: checkout failed"
	head=$(safe_git -C "$tree" rev-parse --verify HEAD)
	[ "$head" = "$commit" ] || die "$name: HEAD is $head, not the pinned $commit"
	# A regular file in the commit, not a link or a directory.
	entry=$(safe_git -C "$tree" ls-tree HEAD -- LICENSE)
	case $entry in
	"100644 blob "* | "100755 blob "*) ;;
	*) die "$name: no LICENSE file" ;;
	esac
	[ -s "$tree/LICENSE" ] || die "$name: LICENSE file is empty"

	fetched+=" $name"
	summary+="$name: commit $commit, licence $license, in .sources/$name"$'\n'
done <<<"$rows"

# Install only after every source has passed.
for name in $fetched; do
	mv -- "$work/$name" "$dest/$name"
done
printf '%s' "$summary"
