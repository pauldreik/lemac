#include <chrono>
#include <vector>

#include <fmt/core.h>

#include <lemac.h>

enum class Strategy { update_and_finalize, oneshot };

std::string_view to_string(Strategy s) {
  using enum Strategy;
  switch (s) {
  case update_and_finalize:
    return "update_and_finalize";
  case oneshot:
    return "oneshot";
  default:
    throw std::runtime_error("oops, did not recognize strategy");
  }
}

struct options {
  Strategy strategy{Strategy::update_and_finalize};
  std::size_t hashsize{123};
  std::chrono::nanoseconds runlength{std::chrono::seconds{1}};
};

struct results {
  std::size_t total_data_bytes{};
  std::size_t total_iterations{};
  std::chrono::duration<double> elapsed{};
  ///@return data speed in byte/s
  double data_rate() const { return total_data_bytes / elapsed.count(); }
  ///@return hash rate in hashes per second
  double hash_rate() const { return elapsed.count() / total_iterations; }
  // we will store the result here, to avoid the optimizer removing our code
  int dummy;
};

results hash(const options& opt) {
  LeMac lemac;

  std::vector<std::uint8_t> data(opt.hashsize);

  std::array<std::uint8_t, 16> out;
  std::array<std::uint8_t, 16> nonce{};
  results ret{};
  std::size_t iterations = 2;
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + opt.runlength;
  while (std::chrono::steady_clock::now() < deadline) {
    for (std::size_t i = 0; i < iterations; ++i) {
      lemac.reset();
      switch (opt.strategy) {
      case Strategy::update_and_finalize:
        lemac.update(data);
        lemac.finalize_to(nonce, out);
        break;
      case Strategy::oneshot:
        out = lemac.oneshot(data, nonce);
        break;
      }
      // prevent the optimizer from removing everything
      nonce[0] = out[0];
    }
    ret.total_iterations += iterations;
    iterations = iterations * 3 / 2;
  }
  const auto t1 = std::chrono::steady_clock::now();
  ret.elapsed = t1 - t0;
  ret.total_data_bytes = ret.total_iterations * opt.hashsize;
  // prevent the optimizer from removing everything
  ret.dummy = out[0];

  return ret;
}

void run_testcase(const options& opt) {
  const auto speed = hash(opt);
  fmt::print("with {:7} byte at a time and strategy {:20}: ", opt.hashsize,
             to_string(opt.strategy));
  fmt::println("hashed with {:6.03f} GiB/s {:6.03f} µs/hash",
               speed.data_rate() * 1e-9, speed.hash_rate() * 1e6);
}

auto get_compiler() {
#if defined(__clang__)
  return "clang";
#elif defined(__GNUC__)
  return "gcc";
#endif
}

void run_all() {
  options opt{};
  for (auto strat : {Strategy::update_and_finalize, Strategy::oneshot}) {
    opt.strategy = strat;
    for (auto size : {1, 1024, 16 * 1024, 256 * 1024, 1024 * 1024}) {
      opt.hashsize = size;
      run_testcase(opt);
    }
  }
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  fmt::println("compiler: {}", get_compiler());
  run_all();
}
