#!/usr/bin/env bash
set -euo pipefail

echo "deploying"
rsync -a --delete ./build/ "$DEPLOY_HOST:/srv/app/"
echo "done"
