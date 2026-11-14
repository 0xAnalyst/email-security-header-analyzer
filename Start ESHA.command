#!/bin/sh
# Double-click in Finder to start ESHA. Close this window or press Ctrl+C to stop.
cd "$(dirname "$0")" || exit 1
sh ./run.sh
status=$?
if [ $status -ne 0 ]; then
  echo
  echo "Press Return to close this window."
  read -r _
fi
