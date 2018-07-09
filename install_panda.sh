#!/bin/bash
set -e

if [ -e requirements.txt ]; then
  pip install -r requirements.txt
fi
pip install -e .
