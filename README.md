# Lemac

This is a C++ implementation of the [lemac cryptographic hash](https://doi.org/10.46586/tosc.v2024.i2.35-67) by Augustin Bariant.

Lemac is very interesting because it utilizes AES hardware acceleration which is very common.

It is based on the public domain code in [https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/](https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/)


# Performance

On an AMD zen4 system, the hashing speed is about 68 GB/s for larger (>100 kB) inputs. This can be compared to the non-cryptographic [xxh3/xxh128 hashes](https://xxhash.com/) which reach about 87 GB/s on the same hardware.

For tiny inputs, the hashing is dominated by the finalization. Calculating a hash for a one byte input takes around 30 ns.

To build and run the benchmark:

    cmake -B build-release -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release
    build-release/benchmark/benchmark

# Support

This code runs with recent clang and gcc versions on amd64 linux.

# Usage

After compilation, there is a binary **lemacsum** which works in similar spirit to sha256sum, xxhsum,  b3sum etc.


# Quality

The goals are (in order)

 1. correctness
 2. run clean with both undefined and address sanitizers
 3. performance
 4. readability and maintainability
 5. portability
