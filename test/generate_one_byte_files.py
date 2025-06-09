#!/usr/bin/env python3

for i in range(256):
    with open(f'one_byte_files/workfile_{i}.bin', "wb") as f:
        f.write(bytes([i]));
