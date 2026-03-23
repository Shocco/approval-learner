#!/bin/bash
# Query the approval learner database
# Usage: approval-query.sh stats|history [N]|reset <cmd>
exec python3 "$(dirname "$0")/../src/approval_learner.py" "$@"
