#!/bin/sh
#
# auto formats cmake files,

set -eu

cd "$(dirname "$0")"/..

# apt install cmake-format
cmake-format -i \
	     CMakeLists.txt \
	     benchmark/CMakeLists.txt \
	     test/CMakeLists.txt \
    ;
