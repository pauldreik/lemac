# Lemac

This is a C++ implementation of the [lemac cryptographic hash](https://doi.org/10.46586/tosc.v2024.i2.35-67) by Augustin Bariant.

Lemac is very interesting because it utilizes AES hardware acceleration which is very common.

The AESNI implementation is based on the public domain code in [https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/](https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/) but has been heavily modified to use C++ and run clean with sanitizers.

# Performance

The bulk speed on a single core is up to about

  * 77 GiB/s, 0.067 cycles per byte (AMD zen 4, Debian 13 Trixie)
  * 44 GiB/s (Apple M3 MacBook Air, macos) 
  * 11 GiB/s, 0.19 cycles per byte (raspberry pi 5, Ubuntu 24.04)

The speed is measured with the included benchmark and using `perf stat` to get the average clock frequency during the test. To build and run the benchmark:

    cmake -B build-release -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release
    build-release/benchmark/benchmark

## Performance characteristics

The cost of the hash is divided into

 1. Initialization (cost is roughly equivalent to hashing 5 kB of extra data) 
 2. Hashing
 3. Finalization (cost is roughly equivalent to hashing 2 kB of extra data)

The initialization cost can mostly be avoided by either reusing an existing hasher object (using `.reset()` followed by `.update()` and `.finalize()`) or simply instantiate one object and copy it before each hash operation.

If all data to be hashed is known up front, the `oneshot()` function is more efficient to use than `update()` followed by `finalize()`.

## Results on AMD zen4

Measurements on an AMD Ryzen 9 7950X3D:
 * lemac 256 kB, oneshot 76.7 GiB/s (median of 5)
 * lemac 1 MB, oneshot 74.3 GiB/s (median of 5)
 * lemac 256 kB, update+finalize 76.6 GiB/s (median of 5)
 * lemac 1 MB, update+finalize 74.3 GiB/s (median of 5)

This can be compared with some other interesting hashes
 * the non-cryptographic [xxh3/xxh128 hashes](https://xxhash.com/) reaches about 89 GiB/s, measured with`xxhsum -b`.  This is about 16% faster than lemac.
 * the non-cryptographic [clhash](https://github.com/simdhash/clhash) which reaches 0.11 cycles per byte using the provided benchmark, which is about 39% slower than lemac.
 * SHA1 measured with `openssl speed -evp SHA1` reaches about 2.8 GiB/s 

The AES performance, as measured by `openssl speed -evp AES-128-ECB` is about 16.4 GiB/s.

## Results on a Apple M3 MacBook Air

Here are the results from a single run with default power settings plugged in to the charger, if that matters. There is some run to run variation, take this with a grain of salt.

```
compiler: clang
with       1 byte at a time and strategy update_and_finalize : hashed with  0.042 GiB/s  0.024 µs/hash
with    1024 byte at a time and strategy update_and_finalize : hashed with 24.588 GiB/s  0.042 µs/hash
with   16384 byte at a time and strategy update_and_finalize : hashed with 42.378 GiB/s  0.387 µs/hash
with  262144 byte at a time and strategy update_and_finalize : hashed with 43.691 GiB/s  6.000 µs/hash
with 1048576 byte at a time and strategy update_and_finalize : hashed with 43.854 GiB/s 23.911 µs/hash
with       1 byte at a time and strategy oneshot             : hashed with  0.021 GiB/s  0.049 µs/hash
with    1024 byte at a time and strategy oneshot             : hashed with 16.297 GiB/s  0.063 µs/hash
with   16384 byte at a time and strategy oneshot             : hashed with 39.348 GiB/s  0.416 µs/hash
with  262144 byte at a time and strategy oneshot             : hashed with 43.242 GiB/s  6.062 µs/hash
with 1048576 byte at a time and strategy oneshot             : hashed with 43.577 GiB/s 24.062 µs/hash
```

## Results on Raspberry Pi 5

This was measured on Ubuntu 24.04. Unfortunately, this was measured with insufficient cooling and the average clock speed was 2.263 GHz according to perf stat.

 * lemac 256 kB, oneshot 11.4 GiB/s (median of 7)
 * lemac 1 MB, oneshot 11.5 GiB/s (median of 7)
 * lemac 256 kB, update+finalize 11.0 GiB/s (median of 7)
 * lemac 1 MB, update+finalize 10.6 GiB/s (median of 7)

The non-cryptographic xxh reaches about 13.2 GiB/s on the same system.

The AES performance, as measured by `openssl speed -evp AES-128-ECB` is about 3.4 GiB/s.

# Hardware and OS support

The code requires C++20. amd64 (AES-NI) is supported (most current desktop cpus), as well as arm64 with cryptographic extensions (like the current apple hardware and raspberry pi 5). Support for other architectures is planned by providing a non-accelerated fallback implementation.

## Linux
The code runs with clang(>=16) and gcc (>=12). It may work with earlier compiler versions, but those are not tested in CI.

## Apple
The code works on apple with xcode and current hardware (apple silicon).
Apple M1 and M3 have been tested successfully.

## Windows
amd64 is supported, arm64 is planned.

# Usage

## Command line tool lemacsum

After compilation, there is a binary **lemacsum** which works in similar spirit to sha256sum, xxhsum,  b3sum etc.

Generate a checksum:

    $ lemacsum file |tee checksum
    5351314614a6de5f31704434c083e7a9  file

Verify a checksum:

    $ lemacsum -c checksum
    file: OK


## As a library

To use this from cmake, add the following snippet to your CMakeLists.txt:

```cmake
include(FetchContent)
FetchContent_Declare(
  lemac
  GIT_REPOSITORY https://github.com/pauldreik/lemac.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(lemac)
target_link_libraries(my_executable PRIVATE lemac)
```

and in your code, using fmt for the nice printout:

```cpp
#include <string>
#include <fmt/ranges.h>
#include "lemac.h"

int main()
{
  std::string message("hello");
  lemac::LeMac lm;
  const auto hash = lm.oneshot(
      std::span((const std::uint8_t*)message.data(), message.size()));

  fmt::println("the hash of {} is {:02x}", message, fmt::join(hash, ""));
  // prints "the hash of hello is b2e64fbf9da60940f54a4cd3ee07c37d"
}
```

# License

Boost 1.0 license, which allows commercial use and modification.

# Quality

The goals are (in order)

 1. correctness
 2. run clean with both undefined and address sanitizers
 3. performance
 4. readability and maintainability
 5. portability
