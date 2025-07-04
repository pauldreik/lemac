#!/bin/sh

set -eu

me=$(basename "$0")
cd "$(dirname "$0")/.."

builddir=build-mingw64
mkdir -p $builddir

# toolchain-mingw64.cmake
cat >$builddir/toolchain-mingw64.cmake <<EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# specify the cross compiler
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# where is the target environment
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

cmake \
  -B $builddir \
  -S . \
  -GNinja \
  -DCMAKE_TOOLCHAIN_FILE=$builddir/toolchain-mingw64.cmake \
  -DLEMAC_BUILD_TESTING=Off \
  -DCMAKE_BUILD_TYPE=Release

cmake --build $builddir
