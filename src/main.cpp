#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

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
  std::cout << "calculates or verifies lemac checksums, behaves similar to "
               "sha256sum\n";
}

namespace {
// RAII for file descriptor
struct fdcloser {
  explicit fdcloser(int fd) : m_fd(fd) {}

  // DesDeMovA to prevent copy

  fdcloser& operator=(fdcloser&&) = delete;

  ~fdcloser() { close(m_fd); }

  int m_fd{-1};
};

// RAII for memory map
struct mmapper {
  mmapper(void* addr, size_t length) : m_addr(addr), m_len(length) {}

  // DesDeMovA to prevent copy
  mmapper& operator=(mmapper&&) = delete;

  ~mmapper() { munmap((void*)m_addr, m_len); }

  void* m_addr{MAP_FAILED};
  size_t m_len{0};
};
} // namespace

// use std::string for filename to guarantee null termination
std::string checksum(lemac::LeMac& lemac, const std::string& filename) {

  lemac.reset();

  // special case "-" to mean stdin, just like sha256sum
  const auto fd = fdcloser{filename == "-" ? dup(STDIN_FILENO)
                                           : open(filename.c_str(), O_RDONLY)};

  if (fd.m_fd == -1) {
    std::cerr << "failed opening file " << filename << ", got error "
              << std::strerror(errno) << '\n';
    return {};
  }

  // get the filesize and kind
  struct stat statbuf{};
  if (fstat(fd.m_fd, &statbuf) != 0) {
    std::cerr << "failed fstat for file " << filename << ", got error "
              << std::strerror(errno) << '\n';
    return {};
  }

  bool use_mmap = false;

  switch (statbuf.st_mode & S_IFMT) {
  case S_IFBLK:
    // block device, works fine
    break;
  case S_IFCHR:
    // character device, works fine. test with /dev/null or /dev/stdin
    break;
  case S_IFDIR:
    std::cerr << filename << " is a directory\n";
    return {};
  case S_IFIFO:
    // FIFO/pipe, works fine (test with mkfifo /tmp/pipe)
    break;
  case S_IFLNK:
    // works fine, we never come here because we open with open() which resolves
    // the symlink
    break;
  case S_IFREG:
    // reqular file, only use mmap if size is strictly positive
    use_mmap = (statbuf.st_size > 0);
    break;
  case S_IFSOCK:
    // socket, won't happen, does not come past open()
    break;
  default:
    std::cerr << "unknown file type " << +(statbuf.st_mode & S_IFMT) << '\n';
    return {};
  }

  if (use_mmap) {
    assert(statbuf.st_size > 0);
    const auto length = static_cast<size_t>(statbuf.st_size);

    const auto memory_map =
        mmapper(mmap(NULL, length, PROT_READ,
                     MAP_FILE | MAP_PRIVATE | MAP_POPULATE, fd.m_fd, 0),
                length);
    if (memory_map.m_addr == MAP_FAILED) {

      std::cerr << "failed memory mapping file " << filename << ", got errno "
                << std::strerror(errno) << ", file size " << statbuf.st_size
                << '\n';
      return {};
    } else {
      const auto* addr =
          reinterpret_cast<const std::uint8_t*>(memory_map.m_addr);
      return tohex(lemac.oneshot(std::span{addr, length}));
    }
  } else if (!use_mmap) {
    std::vector<std::uint8_t> buf(1 << 20);
    for (;;) {
      const auto ret = read(fd.m_fd, buf.data(), buf.size());
      if (ret < 0) {
        std::cerr << "failed reading from " << filename << ", got "
                  << std::strerror(errno) << '\n';
        return {};
      }
      if (ret == 0) {
        // end of file
        break;
      }
      lemac.update(std::span(buf).first(ret));
    }
    return tohex(lemac.finalize());
  } else if (statbuf.st_size < 0) {
    std::cerr << "negative filesize from stat for file " << filename << '\n';
    return {};
  }

  std::cerr << "coming here indicates a programming error\n";

  return {};
}

struct options {
  // see coreutils sha256sum for explanation of these
  bool check = false;
  bool ignore_missing = false;
  bool strict = false;
  // --tag
  bool bsd_style_checksum = false;
  std::vector<const char*> filelist;
};

/// @return true on success
bool verify_checksum_from_file(const options& opt, lemac::LeMac& lemac,
                               const char* filename) {
  bool retval = true;
  std::ifstream list(filename);
  if (!list) {
    std::cerr << "failed opening " << filename << '\n';
    return false;
  }

  while (list) {
    std::string expected_hash;
    std::string item;
    list >> expected_hash;
    bool line_read_ok = true;
    if (list.eof()) {
      // reached the end of the file
      break;
    }
    if (expected_hash.size() != 32) {
      std::cerr << "wrong size of hash " << expected_hash.size() << "\n";
      line_read_ok = false;
    } else if (expected_hash.find_first_not_of("0123456789abcdef") !=
               std::string::npos) {
      std::cerr << "wrong content of hash: \"" << expected_hash << "\"\n";
      line_read_ok = false;
    }
    list.ignore(2);
    std::getline(list, item);
    if (list.bad()) {
      std::cerr << "failed parsing checksum line from " << filename << '\n';
      line_read_ok = false;
    }
    if (!line_read_ok) {
      if (opt.strict) {
        retval = false;
      }
      continue;
    }
    const auto actual_hash = checksum(lemac, std::string(item));
    if (actual_hash.empty()) {
      std::cout << item << ": FAILED open or read\n";
      if (!opt.ignore_missing) {
        retval = false;
      }
    } else {
      if (actual_hash == expected_hash) {
        std::cout << item << ": OK\n";
      } else {
        std::cerr << "got " << actual_hash << " expected " << expected_hash
                  << '\n';
        std::cout << item << ": FAILED\n";
        retval = false;
      }
    }
  }
  return retval;
}

/// @return true on success
bool generate_checksum([[maybe_unused]] const options& opt, lemac::LeMac& lemac,
                       const char* filename) {
  auto answer = checksum(lemac, std::string(filename));
  if (answer.empty()) {
    return false;
  } else {
    // use two spaces, just like sha256sum
    std::cout << answer << "  " << filename << '\n';
    return true;
  }
}

void parse_args(options& opt, int argc, char* argv[]) {
  for (int i = 1; i < argc; ++i) {
    using namespace std::string_view_literals;
    const auto arg = std::string_view(argv[i]);
    if (arg == "-h" || arg == "--help") {
      usage();
      std::exit(EXIT_SUCCESS);
    } else if ("--check"sv == arg || "-c"sv == arg) {
      opt.check = true;
    } else if ("--ignore-missing"sv == arg) {
      opt.ignore_missing = true;
    } else if ("--strict"sv == arg) {
      // exit non-zero for improperly formatted checksum lines
      opt.strict = true;
    } else if ("--"sv == arg) {
      // end of options
      opt.filelist.reserve(argc - i);
      for (; i < argc; ++i) {
        opt.filelist.emplace_back(argv[i]);
      }
      break;
    } else if (arg.starts_with("-") && arg.size() > 1) {
      std::cerr << "did not understand argument " << arg << '\n';
      std::exit(EXIT_FAILURE);
    } else {
      // the rest must be files!
      opt.filelist.reserve(argc - i);
      for (; i < argc; ++i) {
        opt.filelist.emplace_back(argv[i]);
      }
      break;
    }
  } // for

  if (!opt.check) {
    if (opt.ignore_missing) {
      std::cerr << "--ignore-missing can only be used in check mode\n";
      std::exit(EXIT_FAILURE);
    }
  }

  // if no files were given, use stdin (both in --check mode and generation
  // mode)
  if (opt.filelist.empty()) {
    opt.filelist.emplace_back("-");
  }
}

int main(int argc, char* argv[]) {

  options opt;
  parse_args(opt, argc, argv);

  lemac::LeMac lemac;

  if (opt.check) {
    // verify checksums given on a file or stdin
    bool bad = false;
    for (auto f : opt.filelist) {
      if (!verify_checksum_from_file(opt, lemac, f)) {
        bad = true;
      }
    }
    if (bad) {
      std::exit(EXIT_FAILURE);
    }
  } else {
    // generate checksums
    bool bad = false;
    for (auto f : opt.filelist) {
      if (!generate_checksum(opt, lemac, f)) {
        bad = true;
      }
    }
    if (bad) {
      std::exit(EXIT_FAILURE);
    }
  }
}
