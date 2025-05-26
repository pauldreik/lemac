#!/usr/bin/env bash
#
# verifies that the tool behaves as intended

set -eu

me=$(basename "$0")
rootdir=$(dirname "$0")/..

builddir="$rootdir/build-tool-test"
cmake -S "$rootdir" -B "$builddir"
cmake --build "$builddir"

# absolute path to the tool
tooldir=$(
  cd $builddir
  pwd
)
tool="$tooldir/lemacsum"

workdir="$builddir/workdir"
rm -rf "$workdir"
mkdir -p "$workdir"

cd "$workdir"

# check that help works
"$tool" --help >help.txt

compare_files() {
  if ! diff --brief "$1" "$2"; then
    echo "$me: there was an unexpected diff between $1 and $2"
    exit 1
  fi
}

# no args means checksum from stdin
echo "5f4aad4604ceefad43c9336d29671556  -" >expected.txt
echo hej | "$tool" >noargs.txt
compare_files noargs.txt expected.txt

# - means stdin
echo hej | "$tool" - >noargs2.txt
compare_files noargs2.txt expected.txt

# /dev/stdin is maybe debian specific
echo "5f4aad4604ceefad43c9336d29671556  /dev/stdin" >expected.txt
echo hej | "$tool" /dev/stdin >noargs3.txt
compare_files noargs3.txt expected.txt

# hashing multiple files at once
echo hej >hej.txt
"$tool" hej.txt hej.txt >multifiles.txt
echo "5f4aad4604ceefad43c9336d29671556  hej.txt" >tmp.txt
cat tmp.txt tmp.txt >expected.txt
compare_files multifiles.txt expected.txt

# we can hash block devices
"$tool" /dev/null | head -c 32 >null.txt
touch empty
"$tool" empty | head -c 32 >empty.txt
compare_files null.txt empty.txt

# we can hash a pipe
mkfifo pipe
(echo hej >pipe) &
"$tool" pipe >pipe.txt
wait
echo "5f4aad4604ceefad43c9336d29671556  pipe" >expected.txt
compare_files pipe.txt expected.txt

# we can hash a block device, but that is awkward to test in a script like this

# we can hash through a symlink
ln -s hej.txt symlink
"$tool" symlink >symlink.txt
echo "5f4aad4604ceefad43c9336d29671556  symlink" >expected.txt
compare_files symlink.txt expected.txt

# hashing something that does not work should result in fail
echo hej >hej
if "$tool" / hej >dir.txt; then
  echo "$me: expected hashing a directory would fail, but it didn't"
  exit 1
fi
echo "5f4aad4604ceefad43c9336d29671556  hej" >expected.txt
compare_files dir.txt expected.txt

# generate a checksum file and verify it
echo a >a
echo b >b
echo c >c
"$tool" a b c >abc.txt
if ! "$tool" --check abc.txt; then
  echo "$me: expected the verification to go well"
  exit 1
fi
# modify one of the files
echo modified >>b
if "$tool" --check abc.txt; then
  echo "$me: went well, but expected the verification to fail"
  exit 1
fi
# if we remove the file, we should still get an error
rm b
if "$tool" --check abc.txt; then
  echo "$me: went well, but expected the verification to fail"
  exit 1
fi
# ...but with --ignore-missing, "don't fail or report status for missing files"
if ! "$tool" --ignore-missing --check abc.txt; then
  echo "$me: failed, but expected success"
  exit 1
fi

# malformed check list
echo "019837450189735" >malformed.txt
if ! "$tool" --check malformed.txt; then
  echo "$me: failed, expected it to succeed"
  exit 1
fi
if "$tool" --strict --check malformed.txt; then
  echo "$me: succeded, expected it to fail"
  exit 1
fi

echo "$me: all is good!"
