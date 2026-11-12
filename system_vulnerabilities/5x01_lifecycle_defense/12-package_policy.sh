#!/bin/bash
# 12-package_policy.sh - Analyze the apt-cache policy of a package
# Usage: ./12-package_policy.sh <package>
# Read-only: makes no change to the system.

usage() {
	echo "Usage: $0 <package>" >&2
	exit 1
}

die() {
	echo "Error: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] && [ -n "$1" ] || usage
pkg="$1"

for cmd in apt-cache dpkg awk; do
	command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not found"
done

policy=$(LC_ALL=C apt-cache policy "$pkg" 2>/dev/null) || die "apt-cache policy failed for '$pkg'"

installed=$(awk '/^  Installed:/ {print $2; exit}' <<<"$policy")
candidate=$(awk '/^  Candidate:/ {print $2; exit}' <<<"$policy")

[ -n "$installed" ] || [ -n "$candidate" ] || die "package '$pkg' not found in APT cache (try: sudo apt-get update)"

# Parse the version table of the first package block into:
#   version|priority|repository|is_security
table=$(awk '
	NR == 1 { next }
	/^[^ ]/ { exit }
	/^  Version table:/ { intable = 1; next }
	!intable { next }
	/^ \*\*\* / || /^     [^ ]/ {
		flush()
		ver = $(NF - 1); prio = $NF; repo = ""; local = 0; sec = 0
		next
	}
	/^        +-?[0-9]+ / {
		if ($2 ~ /dpkg\/status$/) { local = 1; next }
		suite = $3
		sub(/\/.*/, "", suite)
		if (suite == "" || suite == ".") suite = $2
		if (suite ~ /-security$/) { sec = 1; repo = suite }
		else if (repo == "") repo = suite
	}
	function flush() {
		if (ver == "") return
		if (repo == "") repo = (local ? "local (dpkg status)" : "unknown")
		print ver "|" prio "|" repo "|" sec
	}
	END { flush() }
' <<<"$policy")

# Number of releases between two versions: compare the trailing revision
# number when both share the same base (e.g. 3ubuntu3.14 -> 3ubuntu3.17),
# otherwise count the newer versions present in the version table.
version_delta() {
	local from="$1" to="$2" re='^(.*[^0-9])([0-9]+)$'
	if [[ "$from" =~ $re ]]; then
		local fbase="${BASH_REMATCH[1]}" fnum="${BASH_REMATCH[2]}"
		if [[ "$to" =~ $re ]] && [ "${BASH_REMATCH[1]}" = "$fbase" ]; then
			echo $((10#${BASH_REMATCH[2]} - 10#$fnum))
			return
		fi
	fi
	local n=0 v
	while IFS='|' read -r v _; do
		[ -n "$v" ] || continue
		dpkg --compare-versions "$v" gt "$from" && dpkg --compare-versions "$v" le "$to" && n=$((n + 1))
	done <<<"$table"
	echo "$n"
}

echo "=== Package Policy Analysis ==="
echo
echo "Package: $pkg"
echo "Installed: ${installed:-(none)}"
echo "Candidate: ${candidate:-(none)}"
echo
echo "Available versions:"
printf "  %-25s %-9s %s\n" "Version" "Priority" "Repository"
if [ -n "$table" ]; then
	while IFS='|' read -r v p r _; do
		printf "  %-25s %-9s %s\n" "$v" "$p" "$r"
	done <<<"$table"
else
	echo "  (no versions available)"
fi
echo

# Newest security version strictly newer than the installed one
sec_version=""
if [ -n "$installed" ] && [ "$installed" != "(none)" ]; then
	while IFS='|' read -r v _ _ s; do
		[ "$s" = "1" ] || continue
		dpkg --compare-versions "$v" gt "$installed" || continue
		if [ -z "$sec_version" ] || dpkg --compare-versions "$v" gt "$sec_version"; then
			sec_version="$v"
		fi
	done <<<"$table"
fi

echo "Analysis:"
if [ -z "$installed" ] || [ "$installed" = "(none)" ]; then
	echo "  Security update available: N/A (package not installed)"
	if [ -n "$candidate" ] && [ "$candidate" != "(none)" ]; then
		echo "  Recommendation: Install $candidate if required (apt-get install $pkg)"
	else
		echo "  Recommendation: No installable candidate, check APT sources"
	fi
elif [ -n "$sec_version" ]; then
	echo "  Security update available: YES"
	echo "  Version delta: $(version_delta "$installed" "$sec_version") releases behind security"
	echo "  Recommendation: Update to $sec_version"
elif [ -n "$candidate" ] && [ "$candidate" != "(none)" ] &&
	dpkg --compare-versions "$candidate" gt "$installed"; then
	echo "  Security update available: NO"
	echo "  Version delta: $(version_delta "$installed" "$candidate") releases behind candidate"
	echo "  Recommendation: Non-security update to $candidate, schedule in a maintenance window"
else
	echo "  Security update available: NO"
	echo "  Version delta: 0 releases behind"
	echo "  Recommendation: Up to date, no action required"
fi
