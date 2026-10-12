#!/usr/bin/env sh
# Copies tripwire.py to ~/.agent-tripwire/bin and prints the hook snippet to merge.
# It never edits your CLI settings for you.
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$HOME/.agent-tripwire/bin"
cp "$DIR/tripwire/tripwire.py" "$HOME/.agent-tripwire/bin/tripwire.py"
chmod +x "$HOME/.agent-tripwire/bin/tripwire.py"
[ -f "$HOME/.agent-tripwire/config.json" ] || cp "$DIR/examples/config.json" "$HOME/.agent-tripwire/config.json"
echo "Installed to ~/.agent-tripwire/bin/tripwire.py (config: ~/.agent-tripwire/config.json)"
echo "Claude Code: merge examples/claude-settings.json into ~/.claude/settings.json (\"hooks\" key)"
echo "Codex CLI:   copy examples/codex-hooks.json to ~/.codex/hooks.json (or merge), then open /hooks in Codex and trust them"
echo "Optional:    alias tripwire='python3 ~/.agent-tripwire/bin/tripwire.py'"
