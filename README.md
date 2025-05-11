# Lemac

This is a C++ implementation of the [lemac cryptographic hash](https://doi.org/10.46586/tosc.v2024.i2.35-67) by Augustin Bariant.

Lemac is very interesting because it utilizes AES hardware acceleration which is very common.

It is based on the public domain code in [https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/](https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/) but has been heavily modified to use C++ and run clean with sanitizers.


# Performance

On an AMD zen4 system, the hashing speed is about 68 GB/s for larger (>100 kB) inputs. This can be compared to the non-cryptographic [xxh3/xxh128 hashes](https://xxhash.com/) which reach about 87 GB/s on the same hardware (measured with `xxhsum -b`). For bulk processing, it is slightly faster than the non-cryptographic [clhash](https://github.com/simdhash/clhash) which reaches 0.1 cycles per byte (measured on the same system, with it's provided benchmark).

The time per hash on the system above (using gcc 14) is approximately

 1. Initialization: 74 ns (paid only once, if you can `.reset()` the hasher and reuse it for the next input, like the benchmark does.)
 2. Hashing: around 68 GB/s (0.08 cycles per byte)
 3. Finalization: around 30 ns

For tiny inputs, the hashing is dominated by the initialization and finalization. The cost of initialization corresponds to hashing about 5 kB of extra data. The cost of finalization about 2 kB of extra data.

If all data to be hashed is known up front, the `oneshot()` function is more efficient to use than `update()` followed by `finalize()`.

To build and run the benchmark:

    cmake -B build-release -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release
    build-release/benchmark/benchmark

# Support

This code runs with clang(>=16) and gcc (>=12) on amd64 linux. It requires C++20. It may work with earlier compiler versions, but those are not tested in CI.

# Usage

## Command line tool lemacsum

After compilation, there is a binary **lemacsum** which works in similar spirit to sha256sum, xxhsum,  b3sum etc.

## As a library

Although yet untested, it should be possible to consume this as a cmake subproject.

# License

Boost 1.0 license, which allows commercial use and modification.

# Quality

The goals are (in order)

 1. correctness
 2. run clean with both undefined and address sanitizers
 3. performance
 4. readability and maintainability
 5. portability
