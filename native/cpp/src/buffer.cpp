#include "security_engine/buffer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <stdexcept>

namespace security_engine {
namespace {

constexpr std::array<char, 16> kHexDigits = {'0', '1', '2', '3', '4', '5',
                                             '6', '7', '8', '9', 'a', 'b',
                                             'c', 'd', 'e', 'f'};

void require_within_bounds(std::size_t size) {
  if (size > kMaxBufferBytes) {
    // Throwing keeps the invariant enforced at construction: a Buffer that
    // exists is always within bounds, so no downstream code has to re-check.
    throw std::length_error("buffer exceeds the maximum permitted size");
  }
}

}  // namespace

Buffer::Buffer(const std::vector<std::uint8_t>& data) : data_(data) {
  require_within_bounds(data_.size());
}

Buffer::Buffer(std::string_view text) {
  require_within_bounds(text.size());
  data_.reserve(text.size());
  for (const char character : text) {
    data_.push_back(static_cast<std::uint8_t>(character));
  }
}

std::optional<std::uint8_t> Buffer::at(std::size_t index) const noexcept {
  if (index >= data_.size()) {
    return std::nullopt;
  }
  return data_[index];
}

std::optional<std::size_t> Buffer::find(
    const std::vector<std::uint8_t>& needle) const noexcept {
  if (needle.empty() || needle.size() > data_.size()) {
    return std::nullopt;
  }
  const auto found =
      std::search(data_.begin(), data_.end(), needle.begin(), needle.end());
  if (found == data_.end()) {
    return std::nullopt;
  }
  return static_cast<std::size_t>(std::distance(data_.begin(), found));
}

double Buffer::entropy() const noexcept {
  if (data_.empty()) {
    return 0.0;
  }
  std::array<std::size_t, 256> counts{};
  counts.fill(0);
  for (const std::uint8_t byte : data_) {
    counts[static_cast<std::size_t>(byte)] += 1;
  }
  const double total = static_cast<double>(data_.size());
  double result = 0.0;
  for (const std::size_t count : counts) {
    if (count == 0) {
      continue;
    }
    const double probability = static_cast<double>(count) / total;
    result -= probability * std::log2(probability);
  }
  return result;
}

std::string Buffer::to_hex() const {
  std::string out;
  out.reserve(data_.size() * 2);
  for (const std::uint8_t byte : data_) {
    out.push_back(kHexDigits[static_cast<std::size_t>(byte >> 4U)]);
    out.push_back(kHexDigits[static_cast<std::size_t>(byte & 0x0FU)]);
  }
  return out;
}

bool constant_time_equals(const std::vector<std::uint8_t>& a,
                          const std::vector<std::uint8_t>& b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < a.size(); ++index) {
    difference = static_cast<std::uint8_t>(difference | (a[index] ^ b[index]));
  }
  return difference == 0;
}

}  // namespace security_engine
