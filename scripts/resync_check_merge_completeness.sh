#!/bin/bash
# Prove a merge of an upstream tag left nothing of that tag behind.
#
# WHY THIS EXISTS
#
# The resync's "rewind onto 8.1.3-rc.8" was done by REVERTING the 23 commits
# past the tag, not by rewriting history, so `git merge-base HEAD <tag>` is
# still b00cd9b18 rather than rc.8. Merging a later tag then behaves in a way
# that is easy to misread:
#
#   * where the newer tag CHANGED a file the revert had touched, git raises a
#     conflict and you see it;
#   * where it did NOT, git sees "they did nothing since the base, we removed
#     it" and SILENTLY KEEPS THE REMOVAL.
#
# So a clean-looking merge can quietly ship without files and without hunks the
# tag has. Merging 8.1.3-rc.15 produced 11 conflicts and, behind them, 9 files
# and 38 more file contents that had been dropped this way - including
# waldur_vmware/vim_utils.py, whose absence only surfaced as an ImportError at
# `waldur` startup, and openstack Instance.metadata, which only surfaced as
# makemigrations wanting to remove a field.
#
# HOW IT WORKS
#
# Everything this fork deliberately changes is, by definition, the delta
# between the OLD tag and the pre-merge commit. Anything ELSE that differs from
# the NEW tag after merging is a revert leftover, not a local decision. So:
#
#   (files differing from NEW_TAG) - (files we deliberately changed vs OLD_TAG)
#
# must be empty. It names every file to take from the tag when it is not.
#
#   scripts/resync_check_merge_completeness.sh 8.1.3-rc.8 8.1.3-rc.15 <pre-merge-sha>
#
# Run it after resolving conflicts and before committing the merge. Re-run it
# after taking the files it names, until it reports nothing.

set -euo pipefail

if [ $# -lt 3 ]; then
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'
    exit 1
fi

OLD_TAG="$1"
NEW_TAG="$2"
PRE_MERGE="$3"

for ref in "$OLD_TAG" "$NEW_TAG" "$PRE_MERGE"; do
    git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || {
        echo "ERROR: no such commit: $ref" >&2
        exit 1
    }
done

echo "merge-base with $NEW_TAG: $(git merge-base HEAD "$NEW_TAG")"
echo "  (if this is not $OLD_TAG, the rewind was a revert and this check matters)"
echo

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Files the fork deliberately changed: the delta OLD_TAG -> pre-merge commit.
git diff --name-only "$OLD_TAG" "$PRE_MERGE" | sort > "$work/ours"

# Files present in the tag but missing from the working tree.
git ls-tree -r --name-only "$NEW_TAG" | sort > "$work/tag_files"
git ls-files | sort > "$work/our_files"
comm -23 "$work/tag_files" "$work/our_files" > "$work/missing"

# Files whose CONTENT differs from the tag, minus the ones we meant to change.
git diff --name-only "$NEW_TAG" | sort > "$work/differs"
comm -23 "$work/differs" "$work/ours" > "$work/leftover"

missing=$(wc -l < "$work/missing")
leftover=$(wc -l < "$work/leftover")

if [ "$missing" -gt 0 ]; then
    echo "MISSING - in $NEW_TAG, absent here ($missing):"
    sed 's/^/  /' "$work/missing"
    echo
fi

if [ "$leftover" -gt 0 ]; then
    echo "DIVERGED - differs from $NEW_TAG, not part of this fork's delta ($leftover):"
    sed 's/^/  /' "$work/leftover"
    echo
fi

if [ "$missing" -eq 0 ] && [ "$leftover" -eq 0 ]; then
    echo "Clean: every file of $NEW_TAG is present, and everything that differs"
    echo "from it is something this fork changed on purpose."
    exit 0
fi

echo "Take them from the tag:"
echo
echo "    cat <<'FILES' | while read -r f; do git checkout $NEW_TAG -- \"\$f\"; done"
cat "$work/missing" "$work/leftover"
echo "FILES"
echo
echo "Then re-run this script, and re-run makemigrations --check: a silently"
echo "dropped model field shows up there rather than here."
exit 1
