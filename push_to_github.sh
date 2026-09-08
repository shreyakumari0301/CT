#!/usr/bin/env bash
# Push standalone TCAR repo to GitHub (Hammad2910/TCAR) — NOT CTI-Chatbot.
set -euo pipefail
cd "$(dirname "$0")"
GH="${GH:-$HOME/bin/gh}"
REPO="${REPO:-Hammad2910/TCAR}"
VISIBILITY="${VISIBILITY:-private}"   # private|public

if ! "$GH" auth status >/dev/null 2>&1; then
  echo "GitHub CLI not logged in. Run once:"
  echo "  $GH auth login -h github.com -p https -w"
  echo "Then re-run: bash push_to_github.sh"
  exit 1
fi

if ! "$GH" repo view "$REPO" >/dev/null 2>&1; then
  echo "Creating $REPO ($VISIBILITY)…"
  "$GH" repo create "$REPO" --"$VISIBILITY" --source=. --remote=origin --push
else
  if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "https://github.com/${REPO}.git"
  fi
  git push -u origin main
fi

echo "Done: https://github.com/${REPO}"
