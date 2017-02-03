#!/bin/bash

exec 1>&2

# No tests to update gh-pages
BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null)
if [ "$BRANCH" = "gh-pages" ] ||
   [ -e .git/MERGE_HEAD ]; then
     exit 0
fi

git stash save -k -q
make
RESULT=$?
git stash pop -q

if [ $RESULT -ne 0 ]
then
  echo "Commit refused -- documents don't build successfully."
  echo "To commit anyway, run \"git commit --no-verify\""
  exit 1
fi