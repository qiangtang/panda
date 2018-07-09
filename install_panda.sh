#!/bin/bash
set -e

install_projects() {
  pushd $1
    if [ -e requirements.txt ]; then
      pip install -r requirements.txt
    fi
    pip install -e .
  popd
}

export SCRIPT_DIR=$(cd $(dirname "$0") && pwd)
pushd "$SCRIPT_DIR"
  install_projects "panda"
popd