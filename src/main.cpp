#include <cassert>
#include <iostream>

#include <cstdint>
#include <stdint.h>

#include <lemac.h>

#include <span>

// for mmap to work
#include <fcntl.h>    //open
#include <sys/mman.h> //mmap
#include <sys/stat.h> //fstat
#include <unistd.h>   //close

std::string tohex(std::span<const std::uint8_t> binary) {
  std::string ret;
  char buf[3];
  for (auto c : binary) {
    std::sprintf(buf, "%02x", (unsigned char)c);
    ret.append(buf);
  }
  return ret;
}

void usage() {
  std::cout << "checksums files passed as arguments, prints to stdout\n";
}

std::string run_lemac(std::span<const char> data) {
  uint8_t N[16] = {};
  uint8_t K[16] = {};
  uint8_t T[16] = {};

  context ctx;
  lemac_init(&ctx, K);
  lemac_MAC(&ctx, N, (const uint8_t*)data.data(), data.size(), T);
  const auto lemac = tohex(std::span(T, sizeof(T)));
  return lemac;
}

void checksum(const std::string& filename) {

  // FIXME: make RAII helpers for the cleanup functions

  const int fd = open(filename.c_str(), O_RDONLY);

  // get filesize
  struct stat statbuf{};
  if (fstat(fd, &statbuf) != 0) {
    throw std::runtime_error("failed fstat");
  }
  const auto filesize = statbuf.st_size;
  // FIXME: error checking of filesize
  const auto length = static_cast<size_t>(filesize);

  const char* addr = reinterpret_cast<const char*>(mmap(
      NULL, length, PROT_READ, MAP_FILE | MAP_PRIVATE | MAP_POPULATE, fd, 0));
  if (addr == MAP_FAILED) {
    throw std::runtime_error("failed mapping");
  }

  close(fd);

  // do the checksumming
  const auto answer = run_lemac(std::span{addr, length});
  std::cout << answer << "  " << filename << '\n';

  munmap((void*)addr, length);
}

int main(int argc, char* argv[]) {

  if (argc < 2) {
    usage();
    std::exit(EXIT_FAILURE);
  }
  for (int i = 1; i < argc; ++i) {
    checksum(std::string(argv[i]));
  }
}
