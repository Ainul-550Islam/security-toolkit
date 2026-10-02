// Self-contained test runner for the C++ foundation library.
//
// No external test framework: adding GoogleTest to validate ~200 lines of
// code would mean vendoring a dependency the project does not otherwise need.
// The harness below reports failures with file and line and exits non-zero,
// which is what CI requires.

#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "security_engine/buffer.hpp"
#include "security_engine/engine.hpp"
#include "security_engine/version.hpp"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const std::string& label, int line) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL (line " << line << "): " << label << "\n";
  }
}

#define CHECK(cond) check((cond), #cond, __LINE__)

std::vector<std::uint8_t> bytes_of(const std::string& text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

void test_buffer_construction_and_bounds() {
  const security_engine::Buffer buffer("hello");
  CHECK(buffer.size() == 5);
  CHECK(!buffer.empty());
  CHECK(buffer.at(0).has_value());
  CHECK(buffer.at(0).value() == static_cast<std::uint8_t>('h'));
  // Out-of-range access returns nullopt rather than reading past the end.
  CHECK(!buffer.at(5).has_value());
  CHECK(!buffer.at(100000).has_value());

  const security_engine::Buffer empty;
  CHECK(empty.empty());
  CHECK(empty.size() == 0);
  CHECK(!empty.at(0).has_value());
}

void test_oversized_buffer_is_rejected() {
  bool threw = false;
  try {
    const std::vector<std::uint8_t> oversized(
        security_engine::kMaxBufferBytes + 1, 0U);
    const security_engine::Buffer buffer(oversized);
    (void)buffer;
  } catch (const std::length_error&) {
    threw = true;
  }
  CHECK(threw);
}

void test_find() {
  const security_engine::Buffer buffer("hello world");
  const auto found = buffer.find(bytes_of("world"));
  CHECK(found.has_value());
  CHECK(found.value() == 6);
  CHECK(!buffer.find(bytes_of("absent")).has_value());
  // An empty needle must not match at offset zero.
  CHECK(!buffer.find({}).has_value());
  // A needle longer than the haystack must not overrun.
  CHECK(!buffer.find(bytes_of("hello world and more")).has_value());
}

void test_entropy() {
  const security_engine::Buffer uniform(std::string(128, 'A'));
  CHECK(std::fabs(uniform.entropy()) < 1e-9);

  std::vector<std::uint8_t> all;
  all.reserve(256);
  for (int value = 0; value < 256; ++value) {
    all.push_back(static_cast<std::uint8_t>(value));
  }
  const security_engine::Buffer full(all);
  CHECK(std::fabs(full.entropy() - 8.0) < 1e-9);

  const security_engine::Buffer empty;
  CHECK(std::fabs(empty.entropy()) < 1e-9);
}

void test_hex() {
  const security_engine::Buffer buffer(
      std::vector<std::uint8_t>{0x00, 0x0F, 0xFF});
  CHECK(buffer.to_hex() == "000fff");
  CHECK(security_engine::Buffer().to_hex().empty());
}

void test_constant_time_equals() {
  CHECK(security_engine::constant_time_equals(bytes_of("abc"), bytes_of("abc")));
  CHECK(!security_engine::constant_time_equals(bytes_of("abc"), bytes_of("abd")));
  CHECK(!security_engine::constant_time_equals(bytes_of("abc"), bytes_of("ab")));
  CHECK(security_engine::constant_time_equals({}, {}));
  // Differing only in the final byte must still be detected.
  CHECK(!security_engine::constant_time_equals(bytes_of("aaaaaaaa"),
                                               bytes_of("aaaaaaab")));
}

void test_engine_reports_honestly() {
  const auto descriptor = security_engine::describe();
  CHECK(descriptor.name == "cpp_core");
  CHECK(descriptor.language == "cpp");
  CHECK(descriptor.version == "0.1.0");
  CHECK(descriptor.capabilities.size() == 1);
  CHECK(descriptor.capabilities.at(0) == "buffer_inspect");

  const auto status = security_engine::health();
  // The library must NOT claim to be healthy while no binding exists.
  CHECK(!status.is_healthy());
  CHECK(status.status == security_engine::HealthStatus::kUnavailable);
  CHECK(!status.detail.empty());

  CHECK(security_engine::to_string(security_engine::HealthStatus::kHealthy) ==
        "healthy");
  CHECK(security_engine::to_string(security_engine::HealthStatus::kUnknown) ==
        "unknown");
  CHECK(security_engine::to_string(
            security_engine::HealthStatus::kUnavailable) == "unavailable");
  CHECK(security_engine::to_string(security_engine::HealthStatus::kDegraded) ==
        "degraded");

  // Default-constructed health is unknown, never healthy.
  const security_engine::EngineHealth fresh;
  CHECK(fresh.status == security_engine::HealthStatus::kUnknown);
  CHECK(!fresh.is_healthy());
}

void test_version_constants_match_python_and_rust() {
  CHECK(security_engine::kVersion == "0.1.0");
  CHECK(security_engine::kSchemaVersion == "1");
  CHECK(security_engine::kEngineName == "cpp_core");
}

}  // namespace

int main() {
  test_buffer_construction_and_bounds();
  test_oversized_buffer_is_rejected();
  test_find();
  test_entropy();
  test_hex();
  test_constant_time_equals();
  test_engine_reports_honestly();
  test_version_constants_match_python_and_rust();

  std::cout << "security_engine tests: " << (g_checks - g_failures) << "/"
            << g_checks << " checks passed\n";
  if (g_failures != 0) {
    std::cerr << g_failures << " check(s) FAILED\n";
    return 1;
  }
  return 0;
}
