#!/usr/bin/env bash

SCRIPT_PATH="$(realpath "$0")"
MODULE_DIR="$(dirname "${SCRIPT_PATH:?}")"

#
# FUNCTIONS
#

function check_requirement(){
    if ! eval "$@" >> /dev/null 2>&1 ; then
        echo "! Fatal : missing requirement"
        if [ -n "${*: -1}" ]; then echo "${@: -1}"; fi
        exit 1
    fi
}

#
# MAIN
#

cd "${MODULE_DIR}" || exit
pyversion=$(python --version)
echo "Install falco mitre checker module for: ${pyversion}"

echo ""
wheel="$(find "./dist/" -type f -name "*.whl")"
python -m pip install "${wheel}" --force-reinstall --no-cache-dir

echo ""
echo "OK"
