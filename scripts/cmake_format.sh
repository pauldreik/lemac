#!/bin/sh
#
# auto formats cmake files,

set -eu

cd "$(dirname "$0")"/..

# apt install cmake-format
git ls-files \
  | grep "CMakeLists.txt" \
  | xargs cmake-format -i
