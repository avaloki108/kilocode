#!/usr/bin/env bash
# kilocode_change - new file

set -euo pipefail

# Sync fork with upstream and push to origin (your fork).
# Usage:
#   scripts/sync-upstream.sh            # Update main from upstream and push to origin
#   scripts/sync-upstream.sh --rebase    # Also rebase current branch onto updated main
#
# Remotes expected:
#   origin   -> https://github.com/avaloki108/kilocode.git (your fork)
#   upstream -> https://github.com/Kilo-Org/kilocode.git   (original)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

ensure_remotes() {
  # Set or add origin to your fork
  git remote set-url origin https://github.com/avaloki108/kilocode.git 2>/dev/null || \
    git remote add origin https://github.com/avaloki108/kilocode.git

  # Set or add upstream to original
  git remote set-url upstream https://github.com/Kilo-Org/kilocode.git 2>/dev/null || \
    git remote add upstream https://github.com/Kilo-Org/kilocode.git

  # Default pushes go to origin (your fork)
  git config remote.pushDefault origin
}

update_main_from_upstream() {
  git fetch --prune upstream origin
  # Ensure main exists locally
  if ! git show-ref --verify --quiet refs/heads/main; then
    git checkout -b main origin/main || git checkout main
  else
    git checkout main
  fi

  # Try fast-forward first; fallback to a merge if needed
  if ! git merge --ff-only upstream/main; then
    git merge --no-edit upstream/main
  fi

  # Push updated main to your fork
  git push origin main
}

rebase_current_branch_onto_main() {
  local current_branch
  current_branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ "$current_branch" == "main" ]]; then
    echo "Already on main; nothing to rebase."
    return 0
  fi

  echo "Rebasing branch '$current_branch' onto updated 'main'..."
  git rebase main
  echo "Rebase complete. You may need to force-push: git push --force-with-lease"
}

main() {
  local do_rebase=false
  if [[ ${1:-} == "--rebase" || ${1:-} == "-r" ]]; then
    do_rebase=true
  fi

  ensure_remotes
  update_main_from_upstream

  if [[ "$do_rebase" == true ]]; then
    rebase_current_branch_onto_main
  fi

  echo "Fork sync complete. Remotes:"
  git remote -v
  echo "pushDefault=$(git config --get remote.pushDefault)"
}

main "$@"
