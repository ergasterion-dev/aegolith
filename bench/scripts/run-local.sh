#!/usr/bin/env bash
# One-command runs of the WAF bench against a target on this machine.
#
#   run-local.sh waf    fetch and import the cases, detect against a fresh
#                       enforce target for each configuration, write a report
#   run-local.sh load   import the cases, send them at a fixed rate to a fresh
#                       enforce target, write a report of the load run
#
# Settings, from the environment:
#   SOURCES       sources to use (default "baseline crs gotestwaf generated-legit")
#   OUT           directory to write into (default bench/out)
#   GO            go command (default go)
#   LEGIT_SEED    seed of the generated legitimate requests (default 1)
#   LEGIT_N       number of generated requests asked for (default 5000)
# waf only:
#   DETECT_RPS    ceiling on requests per second (default 500)
#   PREVIOUS      an earlier report.json to compare with (default none)
# load only:
#   DURATION      how long to send (default 1h)
#   RPS           requests per second (default 2000)
#   WORKERS       requests that may be in flight at once (default 64)
#   ATTACK_SHARE  share of requests drawn from attack cases (default 0.1)
#   LOAD_SEED     seed of the choice of cases (default 1)
#   POLICY        Aegolith configuration file of the target (default none)
#
# The script stops only the processes it started, by process ID, also when it
# fails or is interrupted. It needs the network only to fetch the pinned
# sources (crs, gotestwaf). A report is written without the host name, the user
# name or a local path.
set -euo pipefail

die() {
	printf 'run-local: %s\n' "$*" >&2
	exit 1
}

say() {
	printf 'run-local: %s\n' "$*"
}

[ $# -eq 1 ] || die 'usage: run-local.sh waf|load'
mode=$1
case $mode in
waf | load) ;;
*) die 'usage: run-local.sh waf|load' ;;
esac

# The commit of the build and the fetched trees must not depend on git
# variables of the caller, such as those a git hook sets.
for var in $(compgen -e); do
	case $var in GIT_*) unset "$var" ;; esac
done
PATH=$PATH:/usr/sbin:/sbin
unset CDPATH

bench_dir=$(cd -P -- "$(dirname -- "$0")/.." && pwd)
root=$(cd -P -- "$bench_dir/.." && pwd)

GO=${GO:-go}
SOURCES=${SOURCES-"baseline crs gotestwaf generated-legit"}
OUT=${OUT:-$bench_dir/out}
LEGIT_SEED=${LEGIT_SEED:-1}
LEGIT_N=${LEGIT_N:-5000}
DETECT_RPS=${DETECT_RPS:-500}
PREVIOUS=${PREVIOUS:-}
DURATION=${DURATION:-1h}
RPS=${RPS:-2000}
WORKERS=${WORKERS:-64}
ATTACK_SHARE=${ATTACK_SHARE:-0.1}
LOAD_SEED=${LOAD_SEED:-1}
POLICY=${POLICY:-}

# Check the settings before anything is removed or started.
sources=""
for name in ${SOURCES//,/ }; do
	case $name in
	baseline | crs | gotestwaf | generated-legit) ;;
	*) die "unknown source \"$name\"; known: baseline crs gotestwaf generated-legit" ;;
	esac
	case " $sources " in *" $name "*) die "source $name is named twice" ;; esac
	sources=${sources:+$sources }$name
done
[ -n "$sources" ] || die 'SOURCES names no source'
case $OUT in
/*) ;;
*) OUT=$PWD/$OUT ;;
esac
# Lists of files are separated by commas.
case $OUT$bench_dir in *,*) die 'a path with a comma cannot be used' ;; esac
for name in LEGIT_SEED LEGIT_N DETECT_RPS RPS WORKERS LOAD_SEED; do
	[[ ${!name} =~ ^-?[0-9]+$ ]] || die "$name must be a whole number"
done
if [ "$mode" = waf ] && [ -n "$PREVIOUS" ]; then
	[ -f "$PREVIOUS" ] || die 'PREVIOUS names no file'
fi
policy_note="no policy file"
if [ "$mode" = load ] && [ -n "$POLICY" ]; then
	[ -f "$POLICY" ] || die 'POLICY names no file'
	POLICY=$(cd -P -- "$(dirname -- "$POLICY")" && pwd)/$(basename -- "$POLICY")
	case $POLICY in
	"$root"/*) policy_note="policy ${POLICY#"$root"/}" ;;
	*) policy_note="policy file $(basename -- "$POLICY")" ;;
	esac
fi

# has SOURCE reports whether the run uses the source.
has() {
	case " $sources " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

work=""
target_pid=""
client_pid=""

# stop PID ends a process this script started and waits for it; one that does
# not end within about 30 s of SIGTERM is killed.
stop() {
	local pid=$1 i
	[ -n "$pid" ] || return 0
	kill -TERM "$pid" 2>/dev/null || true
	for ((i = 0; i < 300; i++)); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -KILL "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

cleanup() {
	local status=$?
	trap '' INT TERM
	# The client first, so that it does not meet a closed target.
	stop "$client_pid"
	stop "$target_pid"
	[ -z "$work" ] || rm -rf -- "$work"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

work=$(mktemp -d "${TMPDIR:-/tmp}/aegobench.XXXXXX")
mkdir -p -- "$OUT"
OUT=$(cd -P -- "$OUT" && pwd)

# A run that fails must not leave an earlier report that looks like its own.
if [ "$mode" = waf ]; then
	report_dir=$OUT
	if [ -n "$PREVIOUS" ]; then
		cp -- "$PREVIOUS" "$work/previous.json"
	fi
else
	report_dir=$OUT/load
	rm -f -- "$OUT/load/load.json"
fi
rm -f -- "$report_dir/report.md" "$report_dir/report.json"

# sysctl_value NAME and the functions below describe the machine. Nothing they
# print names the host, the user or a path.
sysctl_value() {
	sysctl -n "$1" 2>/dev/null || true
}

cpu_model() {
	local v
	v=$(sysctl_value machdep.cpu.brand_string)
	if [ -z "$v" ] && [ -r /proc/cpuinfo ]; then
		v=$(awk -F': *' '/^model name/ {print $2; exit}' /proc/cpuinfo)
	fi
	printf '%s' "${v:-unknown}"
}

physical_cores() {
	local v
	v=$(sysctl_value hw.physicalcpu)
	if [ -z "$v" ] && command -v lscpu >/dev/null 2>&1; then
		v=$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l | tr -d ' ')
	fi
	printf '%s' "${v:-unknown}"
}

logical_processors() {
	local v
	v=$(sysctl_value hw.logicalcpu)
	if [ -z "$v" ]; then
		v=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
	fi
	printf '%s' "${v:-unknown}"
}

memory() {
	local bytes
	bytes=$(sysctl_value hw.memsize)
	if [ -z "$bytes" ] && [ -r /proc/meminfo ]; then
		bytes=$(awk '/^MemTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
	fi
	if [ -z "$bytes" ]; then
		printf 'unknown'
		return
	fi
	awk -v b="$bytes" 'BEGIN {printf "%.1f GiB", b / 1073741824}'
}

operating_system() {
	if command -v sw_vers >/dev/null 2>&1; then
		printf '%s %s (build %s)' "$(sw_vers -productName)" "$(sw_vers -productVersion)" "$(sw_vers -buildVersion)"
	elif [ -r /etc/os-release ]; then
		sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release
	else
		printf 'unknown'
	fi
}

load_average() {
	local v=""
	if [ -r /proc/loadavg ]; then
		v=$(awk '{print $1, $2, $3}' /proc/loadavg)
	else
		v=$(sysctl_value vm.loadavg | awk '{print $2, $3, $4}')
	fi
	printf '%s' "${v:-unknown}"
}

tool_version() {
	command -v "$1" >/dev/null 2>&1 || {
		printf 'not installed'
		return
	}
	"$1" --version | head -n 1
}

say 'building aegobench'
bin=$work/aegobench
(cd -- "$bench_dir" && GOWORK=off "$GO" build -buildvcs=true -o "$bin" ./cmd/aegobench)

if has crs || has gotestwaf; then
	say 'fetching the pinned sources'
	"$bench_dir/scripts/fetch-sources.sh"
fi

cases_dir=$OUT/cases
mkdir -p -- "$cases_dir"
case_files=""
skipped_files=""
for name in baseline crs gotestwaf generated-legit; do
	rm -f -- "$cases_dir/$name.jsonl" "$cases_dir/$name-skipped.jsonl"
done
for name in $sources; do
	file=$cases_dir/$name.jsonl
	skipped=$cases_dir/$name-skipped.jsonl
	case $name in
	baseline) "$bin" import --source baseline --corpus "$root/testdata/corpus" --out "$file" --skipped "$skipped" ;;
	crs | gotestwaf) "$bin" import --source "$name" --root "$bench_dir/.sources/$name" --out "$file" --skipped "$skipped" ;;
	generated-legit) "$bin" import --source generated-legit --seed "$LEGIT_SEED" --n "$LEGIT_N" --out "$file" ;;
	esac
	case_files=${case_files:+$case_files,}$file
	if [ "$name" != generated-legit ]; then
		skipped_files=${skipped_files:+$skipped_files,}$name=$skipped
	fi
done

# start_target DIR ACCESS [POLICY] starts a target on free loopback ports,
# writing its logs, and waits until it listens. It sets target_pid, base and
# admin.
start_target() {
	local dir=$1 access=$2 policy=${3:-} line=""
	local args=(target --addr 127.0.0.1:0 --admin-addr 127.0.0.1:0 --mode enforce
		--access "$access" --decisions "$dir/decisions.jsonl")
	if [ -n "$policy" ]; then
		args+=(--policy "$policy")
	fi
	: >"$dir/target.log"
	"$bin" "${args[@]}" >"$dir/target.log" 2>&1 &
	target_pid=$!
	printf '%s\n' "$target_pid" >"$dir/target.pid"
	while :; do
		line=$(sed -n 's|^target listening on \(http://[^ ]*\) (mode enforce), admin on \(http://[^ ]*\)$|\1 \2|p' "$dir/target.log")
		[ -z "$line" ] || break
		if ! kill -0 "$target_pid" 2>/dev/null; then
			cat "$dir/target.log" >&2
			die 'the target ended before it listened'
		fi
		sleep 0.1
	done
	base=${line% *}
	admin=${line#* }
}

# stop_target DIR ends the target, which must have run until now and end well.
stop_target() {
	local status=0
	kill -TERM "$target_pid" 2>/dev/null || {
		cat "$1/target.log" >&2
		die 'the target ended during the run'
	}
	wait "$target_pid" || status=$?
	target_pid=""
	if [ "$status" -ne 0 ]; then
		cat "$1/target.log" >&2
		die "the target ended with status $status"
	fi
}

# run_client DIR LOG ARGS... runs one aegobench command against the target in
# the background, so that an interrupt is acted on at once.
run_client() {
	local dir=$1 log=$2 status=0
	shift 2
	"$bin" "$@" >"$dir/$log.log" 2>&1 &
	client_pid=$!
	printf '%s\n' "$client_pid" >"$dir/$log.pid"
	wait "$client_pid" || status=$?
	client_pid=""
	cat "$dir/$log.log"
	[ "$status" -eq 0 ] || die "$log ended with status $status"
}

report_args=(report --cases "$case_files" --out "$report_dir" --sources "$bench_dir/sources.json"
	--environment "$work/environment")
if [ -n "$skipped_files" ]; then
	report_args+=(--skipped "$skipped_files")
fi
if has generated-legit; then
	report_args+=(--legit-seed "$LEGIT_SEED" --legit-n "$LEGIT_N")
fi

load_at_start=$(load_average)

if [ "$mode" = waf ]; then
	results=""
	logs=()
	for config in no-policy example-policy; do
		dir=$OUT/runs/$config
		mkdir -p -- "$dir"
		rm -f -- "$dir"/{access,decisions,results}.jsonl "$dir"/{target,detect}.{log,pid}
		policy=""
		if [ "$config" = example-policy ]; then
			policy=$root/testdata/corpus/example-api-policy.json
		fi
		say "detecting, configuration $config"
		start_target "$dir" "$dir/access.jsonl" "$policy"
		run_client "$dir" detect detect --cases "$case_files" --base "$base" --rps "$DETECT_RPS" \
			--access "$dir/access.jsonl" --decisions "$dir/decisions.jsonl" --out "$dir/results.jsonl"
		stop_target "$dir"
		results=${results:+$results,}$config=$dir/results.jsonl
		logs+=("$dir/detect.log")
	done
	report_args+=(--results "$results")
	if [ -n "$PREVIOUS" ]; then
		report_args+=(--previous "$work/previous.json")
	fi
else
	dir=$OUT/load
	mkdir -p -- "$dir"
	rm -f -- "$dir"/decisions.jsonl "$dir"/{target,load}.{log,pid}
	say "sending $RPS requests per second for $DURATION"
	# The access log is not read by a load run and would grow without bound.
	start_target "$dir" /dev/null "$POLICY"
	run_client "$dir" load load --cases "$case_files" --base "$base" --admin "$admin" \
		--decisions "$dir/decisions.jsonl" --rps "$RPS" --duration "$DURATION" --workers "$WORKERS" \
		--attack-share "$ATTACK_SHARE" --seed "$LOAD_SEED" --out "$dir/load.json"
	stop_target "$dir"
	report_args+=(--load "$dir/load.json")
fi

load_at_end=$(load_average)

built_with=$("$GO" version -m "$bin" | awk 'NR == 1 {print $NF}')
libinjection=$("$GO" version -m "$bin" |
	awk '$1 == "dep" && $2 == "github.com/corazawaf/libinjection-go" {print $3}')
{
	printf 'CPU=%s\n' "$(cpu_model)"
	printf 'Physical cores=%s\n' "$(physical_cores)"
	printf 'Logical processors=%s\n' "$(logical_processors)"
	printf 'Memory=%s\n' "$(memory)"
	printf 'Operating system=%s\n' "$(operating_system)"
	printf 'Kernel=%s\n' "$(uname -sr)"
	printf 'Architecture=%s\n' "$(uname -m)"
	printf 'Go=%s\n' "${built_with:-unknown}"
	printf 'libinjection-go=%s\n' "${libinjection:-unknown}"
	printf 'git=%s\n' "$(tool_version git)"
	printf 'jq=%s\n' "$(tool_version jq)"
	printf 'bash=%s\n' "$BASH_VERSION"
	printf 'Load average at start (1, 5, 15 min)=%s\n' "$load_at_start"
	printf 'Load average at end (1, 5, 15 min)=%s\n' "$load_at_end"
	printf 'Command=bench/scripts/run-local.sh %s\n' "$mode"
	printf 'Sources=%s\n' "$sources"
	if [ "$mode" = waf ]; then
		printf 'Configuration no-policy=enforce mode, no policy file\n'
		printf 'Configuration example-policy=enforce mode, policy testdata/corpus/example-api-policy.json\n'
		printf 'Detection rate ceiling=%s requests per second\n' "$DETECT_RPS"
		printf 'Target and client=separate processes on this machine, over loopback; a fresh target and fresh logs for each configuration\n'
	else
		printf 'Target=enforce mode, %s; access log discarded, decision log written\n' "$policy_note"
		printf 'Target and client=separate processes on this machine, over loopback\n'
		printf 'Load settings=%s requests per second for %s, %s workers, attack share %s, seed %s\n' \
			"$RPS" "$DURATION" "$WORKERS" "$ATTACK_SHARE" "$LOAD_SEED"
	fi
} >"$work/environment"

"$bin" "${report_args[@]}"
say "the report is report.md and report.json in the output directory"

# An unknown outcome means the logs do not say what happened to a case; such a
# run is not to be published.
if [ "$mode" = waf ]; then
	for log in "${logs[@]}"; do
		grep -q ', 0 unknown, ' "$log" || die "a detection run has unknown outcomes; see detect.log in $OUT/runs and run again"
	done
fi
