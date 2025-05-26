#!/bin/sh
#
# clang formats C++ files,

set -eu

cd "$(dirname "$0")"/..

# apt install clang-format-X
CF=notfound
for v in $(seq 30 -1 18) ; do
    if which clang-format-$v >/dev/null; then
	CF=clang-format-$v
    fi
done

if [ $CF = notfound ] ; then
    if which clang-format >/dev/null; then
	CF=clang-format
    else
	echo "please install clang format"
	exit 1
    fi
fi

git ls-files | grep -E "\.(cpp|h)$" | xargs $CF -i
