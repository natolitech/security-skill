#!/bin/bash
# Install the security-review skills into a project's .claude/commands/
#
# Usage:
#   ./install.sh [project-dir] [security-skill-dir]
#
# Both arguments default sensibly: project-dir defaults to the current
# directory, and security-skill-dir defaults to this script's location
# (i.e., the repo root).

set -euo pipefail

PROJECT_DIR="${1:-.}"
SKILL_DIR="${2:-$(cd "$(dirname "$0")" && pwd)}"

COMMANDS_DIR="$PROJECT_DIR/.claude/commands"
SRC_DIR="$SKILL_DIR/.claude/commands"

for f in security-review.md threat-model.md; do
  if [ ! -f "$SRC_DIR/$f" ]; then
    echo "Error: skill file not found at $SRC_DIR/$f" >&2
    echo "Is the security-skill repo cloned, or pass its path as the second argument?" >&2
    exit 1
  fi
done

mkdir -p "$COMMANDS_DIR"
cp "$SRC_DIR/security-review.md" "$COMMANDS_DIR/"
cp "$SRC_DIR/threat-model.md" "$COMMANDS_DIR/"

echo "Security skills installed to $COMMANDS_DIR"
echo "Available commands: /security-review, /threat-model"
echo "Installed versions:"
grep -h "^<!-- skill:" "$COMMANDS_DIR/security-review.md" "$COMMANDS_DIR/threat-model.md" || true
