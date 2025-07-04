#!/usr/bin/env bash
#
# verifies that the tool behaves as intended

set -eu

me=$(basename "$0")
# absolute path to the rootdir of the repo
rootdir=$(dirname "$0")/..
rootdir=$(cd "$rootdir" && pwd)

if [ $# -eq 1 ]; then
  # an existing build is to be tested (can be relative or absolute)
  # Convert to absolute path
  if [[ "$1" = /* ]]; then
    # Already absolute
    tool="$1"
  else
    # Relative path - make it absolute
    tool="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
  fi
  workdir=$rootdir/build-tool-test
else
  builddir="$rootdir/build-tool-test"
  cmake -S "$rootdir" -B "$builddir" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$builddir"

  # absolute path to the tool
  tooldir=$(
    cd $builddir
    pwd
  )
  tool="$tooldir/lemacsum"
  workdir="$builddir/workdir"
fi

rm -rf "$workdir"
mkdir -p "$workdir"

cd "$workdir"

echo "$me: checking that --help works..."
"$tool" --help >help.txt

compare_files() {
  if ! diff --brief "$1" "$2"; then
    echo "$me: there was an unexpected diff between $1 and $2"
    exit 1
  fi
}

echo "$me: check that no args implies checksumming stdin..."
echo "5f4aad4604ceefad43c9336d29671556  -" >expected.txt
echo hej | "$tool" >noargs.txt
compare_files noargs.txt expected.txt

# - means stdin
echo "$me: check that arg \"-\" implies checksumming stdin..."
echo hej | "$tool" - >noargs2.txt
compare_files noargs2.txt expected.txt

# /dev/stdin is maybe debian specific
if [ -e /dev/stdin ]; then
  echo "$me: check that arg /dev/stdin works..."
  echo "5f4aad4604ceefad43c9336d29671556  /dev/stdin" >expected.txt
  echo hej | "$tool" /dev/stdin >noargs3.txt
  compare_files noargs3.txt expected.txt
fi

echo "$me: check that checksumming multiple files at once works..."
echo hej >hej.txt
"$tool" hej.txt hej.txt >multifiles.txt
echo "5f4aad4604ceefad43c9336d29671556  hej.txt" >tmp.txt
cat tmp.txt tmp.txt >expected.txt
compare_files multifiles.txt expected.txt

echo "$me: check that block devices can be checksummed..."
"$tool" /dev/null | head -c 32 >null.txt
touch empty
"$tool" empty | head -c 32 >empty.txt
compare_files null.txt empty.txt

echo "$me: check that pipes can be checksummed..."
mkfifo pipe
(echo hej >pipe) &
"$tool" pipe >pipe.txt
wait
echo "5f4aad4604ceefad43c9336d29671556  pipe" >expected.txt
compare_files pipe.txt expected.txt

echo "$me: check that symlinks can be checksummed..."
ln -s hej.txt symlink
"$tool" symlink >symlink.txt
echo "5f4aad4604ceefad43c9336d29671556  symlink" >expected.txt
compare_files symlink.txt expected.txt

echo "$me: check that checksumming a directory fails..."
echo hej >hej
if "$tool" / hej >dir.txt; then
  echo "$me: expected hashing a directory would fail, but it didn't"
  exit 1
fi
echo "5f4aad4604ceefad43c9336d29671556  hej" >expected.txt
compare_files dir.txt expected.txt

echo "$me: check that a checksum file can be checked..."
echo a >a
echo b >b
echo c >c
"$tool" a b c >abc.txt
if ! "$tool" --check abc.txt; then
  echo "$me: expected the verification to go well"
  exit 1
fi
echo "$me: check that a modified file is detected..."
echo modified >>b
if "$tool" --check abc.txt; then
  echo "$me: went well, but expected the verification to fail"
  exit 1
fi
echo "$me: check that a missing file is detected..."
rm b
if "$tool" --check abc.txt; then
  echo "$me: went well, but expected the verification to fail"
  exit 1
fi
echo "$me: check that a missing file is ok if --ignore-missing is used..."
if ! "$tool" --ignore-missing --check abc.txt; then
  echo "$me: failed, but expected success"
  exit 1
fi

echo "$me: check that a malformed checksum file is tolerated (just like sha256sum)..."
echo "019837450189735" >malformed.txt
if ! "$tool" --check malformed.txt; then
  echo "$me: failed, expected it to succeed"
  exit 1
fi
echo "$me: check that --strict rejects a malformed checksum file..."
if "$tool" --strict --check malformed.txt; then
  echo "$me: succeded, expected it to fail"
  exit 1
fi

# verify the one byte files
echo "$me: testing all possible one byte files..."
testdatadir="$rootdir/test/"
if [ $(ls "$testdatadir"/one_byte_files/ | grep .bin | wc -l) -ne 256 ]; then
  (
    cd "$testdatadir"
    ./generate_one_byte_files.py
  )
fi
# ensure the one byte files are distinct, so nothing fishy is going on with the generation
cut -f1 -d' ' "$testdatadir"/one_byte_files.lemacsum | sort | uniq >$workdir/tmp
if [ $(wc -l <tmp) -ne 256 ]; then
  echo "$me: hashes are not distinct"
  exit 1
fi
(
  cd "$testdatadir"
  "$tool" --strict --check one_byte_files.lemacsum >$workdir/one_byte_check
)
count=$(grep OK one_byte_check | wc -l)
if [ $count -ne 256 ]; then
  echo "$me: failed count, expected 256 but got $count"
  exit 1
fi

echo "$me: all is good!"
