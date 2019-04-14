#!/bin/bash
set -euf -o pipefail

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

~/google-cloud-sdk/bin/gcloud app deploy --project=goiap-demo --promote "${DIR}/app_secret.yaml"
