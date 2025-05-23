#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <immintrin.h>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif

/**
 * A cryptographic hash function designed by Augustin Bariant
 */
class LeMac {
public:
  /// the size of the key in bytes
  static constexpr std::size_t key_size = 16;

  /**
   * constructs a hasher with a correctly sized key
   * @param key the key does not need to be aligned
   */
  explicit LeMac(std::span<const std::uint8_t, key_size> key = std::span{
                     zero_key}) noexcept;

  /**
   * constructs a hasher with a correctly sized key, verified at runtime.
   * If the size of the key is statically known to be correct, use the other
   * constructor.
   *
   * @param key the key does not need to be aligned, but it must have the
   * correct size. if not, an exception is thrown.
   */
  explicit LeMac(std::span<const std::uint8_t> key);

  /**
   * updates the hash with the provided data. this may be called zero or more
   * times.
   *
   * if all data is known up front, prefer the oneshot() function instead which
   * is faster.
   *
   * @param data does not need to be aligned
   */
  void update(std::span<const std::uint8_t> data) noexcept;

  /**
   * finalizes the hash and returns the result
   * @param nonce does not need to be aligned
   * @return
   */
  std::array<std::uint8_t, 16>
  finalize(std::span<const std::uint8_t> nonce = std::span{zero_key});

  /**
   * finalizes the hash and writes the result into the provided target
   * @param nonce does not need to be aligned
   * @param target does not need to be aligned
   */
  void finalize_to(std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t, 16> target) noexcept;

  /**
   * hashes with the provided data and then finalizes the hash.
   * this is more efficient than update()+finalize() and should be preferred
   * when all data is known upfront.
   *
   * @param data does not need to be aligned
   * @param nonce does not need to be aligned
   * @return
   */
  std::array<std::uint8_t, 16> oneshot(
      std::span<const std::uint8_t> data,
      std::span<const std::uint8_t> nonce = std::span{zero_key}) const noexcept;

  /**
   * resets the object as if it had been newly constructed. this is more
   * efficent than creating a new object.
   */
  void reset() noexcept;

  static constexpr std::array<const std::uint8_t, key_size> zero_key{};

  struct Sstate {
    __m128i S[9];
  };

  struct Rstate {
    void reset();
    __m128i RR;
    __m128i R0;
    __m128i R1;
    __m128i R2;
  };

  // this is the state that changes during absorption of data
  struct ComboState {
    Sstate s;
    Rstate r;
  };

  // this is inited on lemac construction and not changed after
  struct LeMacContext {
    Sstate init;
    __m128i keys[2][11];
    __m128i subkeys[18];

    template <std::size_t i>
      requires(i >= 0 && i <= 8)
    std::span<const __m128i, 11> get_subkey() const {
      return std::span<const __m128i, 11>(subkeys + i, 11);
    }
  };

private:
  void init(std::span<const std::uint8_t, key_size> key) noexcept;
  static constexpr std::size_t block_size = 64;

  void tail(const LeMacContext& context, Sstate& state,
            std::span<const std::uint8_t> nonce,
            std::span<std::uint8_t, 16> target) const noexcept;
  LeMacContext m_context;
  ComboState m_state;
  /// this is a buffer that keeps data between update() invocations,
  /// in case data is provided in sizes not evenly divisible by the block size
  std::array<std::uint8_t, block_size> m_buf{};
  std::size_t m_bufsize{};
};

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
