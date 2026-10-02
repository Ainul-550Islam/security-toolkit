// Bounded, owning byte buffer.
//
// Raw `new`/`delete` and naked pointer arithmetic are exactly how C++ security
// tooling grows memory-corruption bugs. This type uses RAII (std::vector owns
// the storage), bounds-checked accessors, and no manual memory management, so
// the common failure modes are structurally impossible rather than merely
// avoided by care.
#ifndef SECURITY_ENGINE_BUFFER_HPP
#define SECURITY_ENGINE_BUFFER_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace security_engine {

// Largest buffer this library will accept (1 MiB), mirroring the Rust crate.
inline constexpr std::size_t kMaxBufferBytes = 1024u * 1024u;

class Buffer {
 public:
  Buffer() = default;

  // Throws std::length_error when data exceeds kMaxBufferBytes.
  explicit Buffer(const std::vector<std::uint8_t>& data);
  explicit Buffer(std::string_view text);

  // Copy and move are all defaulted: std::vector already handles ownership
  // correctly, so the rule of zero applies.
  Buffer(const Buffer&) = default;
  Buffer& operator=(const Buffer&) = default;
  Buffer(Buffer&&) noexcept = default;
  Buffer& operator=(Buffer&&) noexcept = default;
  ~Buffer() = default;

  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
  [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept {
    return data_;
  }

  // Bounds-checked read. Returns std::nullopt out of range instead of
  // reading past the end.
  [[nodiscard]] std::optional<std::uint8_t> at(std::size_t index) const noexcept;

  // Index of the first occurrence of needle, or std::nullopt.
  [[nodiscard]] std::optional<std::size_t> find(
      const std::vector<std::uint8_t>& needle) const noexcept;

  // Shannon entropy in bits per byte (0.0 for an empty buffer).
  [[nodiscard]] double entropy() const noexcept;

  // Lowercase hexadecimal rendering.
  [[nodiscard]] std::string to_hex() const;

 private:
  std::vector<std::uint8_t> data_;
};

// Comparison in time independent of content, for signatures and tokens.
[[nodiscard]] bool constant_time_equals(const std::vector<std::uint8_t>& a,
                                        const std::vector<std::uint8_t>& b) noexcept;

}  // namespace security_engine

#endif  // SECURITY_ENGINE_BUFFER_HPP
