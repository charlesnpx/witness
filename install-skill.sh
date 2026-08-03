#!/usr/bin/env bash
set -euo pipefail

NAME="witness"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VERSION="${WITNESS_VERSION:-$(git -C "$repo_root" describe --tags --exact-match 2>/dev/null || true)}"
VERSION="${VERSION:-dev}"

OPERATION="install"
TARGET="all"
JSON="false"
INSTALL_ROOT=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--plan)
			OPERATION="plan"
			shift
			;;
		--install)
			OPERATION="install"
			shift
			;;
		--uninstall)
			OPERATION="uninstall"
			shift
			;;
		--target)
			TARGET="${2:?missing --target value}"
			shift 2
			;;
		--json)
			JSON="true"
			shift
			;;
		--install-root)
			INSTALL_ROOT="${2:?missing --install-root value}"
			shift 2
			;;
		*)
			printf 'error: unknown argument: %s\n' "$1" >&2
			exit 1
			;;
	esac
done

[[ "$JSON" != "true" ]] && {
	printf 'error: this installer requires --json\n' >&2
	exit 1
}

case "$TARGET" in
	all | codex | claude | tools) ;;
	*)
		printf 'error: unsupported target: %s\n' "$TARGET" >&2
		exit 1
		;;
esac

home_root="${INSTALL_ROOT:-$HOME}"

bin_path="$home_root/.local/bin/$NAME"
harness_bin_path="$home_root/.local/bin/witness-harness"
codex_skill_path="$home_root/.codex/skills/$NAME/SKILL.md"
codex_bundle_path="$home_root/.codex/skills/$NAME/bundle/relay-integration-bundle-v2.json"
claude_skill_path="$home_root/.claude/skills/$NAME/SKILL.md"
claude_bundle_path="$home_root/.claude/skills/$NAME/bundle/relay-integration-bundle-v2.json"

include_tools="false"
include_codex="false"
include_claude="false"

case "$TARGET" in
	all)
		include_tools="true"
		include_codex="true"
		include_claude="true"
		;;
	tools)
		include_tools="true"
		;;
	codex)
		include_codex="true"
		;;
	claude)
		include_claude="true"
		;;
esac

json_escape() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//\"/\\\"}"
	value="${value//$'\n'/\\n}"
	printf '%s' "$value"
}

sha_file() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		printf 'error: shasum or sha256sum is required\n' >&2
		exit 1
	fi
}

install_target_files() {
	if [[ "$include_tools" == "true" ]]; then
		mkdir -p "$(dirname "$bin_path")"
		go build -o "$bin_path" "$repo_root/cmd/witness"
		go build -o "$harness_bin_path" "$repo_root/cmd/witness-harness"
	fi
	if [[ "$include_codex" == "true" ]]; then
		mkdir -p "$(dirname "$codex_bundle_path")"
		install -m 0644 "$repo_root/skill/SKILL.md" "$codex_skill_path"
		install -m 0644 "$repo_root/skill/bundle/relay-integration-bundle-v2.json" "$codex_bundle_path"
	fi
	if [[ "$include_claude" == "true" ]]; then
		mkdir -p "$(dirname "$claude_bundle_path")"
		install -m 0644 "$repo_root/skill/SKILL.md" "$claude_skill_path"
		install -m 0644 "$repo_root/skill/bundle/relay-integration-bundle-v2.json" "$claude_bundle_path"
	fi
}

uninstall_target_files() {
	if [[ "$include_tools" == "true" ]]; then
		rm -f "$bin_path" "$harness_bin_path"
	fi
	if [[ "$include_codex" == "true" ]]; then
		rm -f "$codex_skill_path" "$codex_bundle_path"
	fi
	if [[ "$include_claude" == "true" ]]; then
		rm -f "$claude_skill_path" "$claude_bundle_path"
	fi
}

emit_file() {
	local path="$1"
	printf '{"path":"%s"' "$(json_escape "$path")"
	if [[ "$OPERATION" == "install" && -f "$path" ]]; then
		printf ',"sha256":"%s"' "$(sha_file "$path")"
	fi
	printf '}'
}

emit_target() {
	local target_name="$1"
	shift
	printf '"%s":{"files":[' "$target_name"
	local first_file="true"
	local path
	for path in "$@"; do
		if [[ "$first_file" != "true" ]]; then
			printf ','
		fi
		first_file="false"
		emit_file "$path"
	done
	printf ']}'
}

emit_report() {
	printf '{"schema":1,"name":"%s","version":"%s","operation":"%s","kind":"delegated","capabilities":["review"],"setup":[{"kind":"executable","executable":"convo-relay","required_for":["review"],"remediation":"Install convo-relay (mise-en-place install convo-relay); witness verification recipes run through it."}],"targets":{' \
		"$(json_escape "$NAME")" "$(json_escape "$VERSION")" "$(json_escape "$OPERATION")"

	local first_target="true"
	if [[ "$include_tools" == "true" ]]; then
		if [[ "$first_target" != "true" ]]; then
			printf ','
		fi
		first_target="false"
		emit_target "tools" "$bin_path" "$harness_bin_path"
	fi
	if [[ "$include_codex" == "true" ]]; then
		if [[ "$first_target" != "true" ]]; then
			printf ','
		fi
		first_target="false"
		emit_target "codex" "$codex_skill_path" "$codex_bundle_path"
	fi
	if [[ "$include_claude" == "true" ]]; then
		if [[ "$first_target" != "true" ]]; then
			printf ','
		fi
		emit_target "claude" "$claude_skill_path" "$claude_bundle_path"
	fi

	printf '},"warnings":[]}\n'
}

case "$OPERATION" in
	plan)
		;;
	install)
		install_target_files
		;;
	uninstall)
		uninstall_target_files
		;;
esac

emit_report
