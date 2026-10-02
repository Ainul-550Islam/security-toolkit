// Engine description and health, mirroring interfaces/engine.py and
// schemas/health.schema.json.
#ifndef SECURITY_ENGINE_ENGINE_HPP
#define SECURITY_ENGINE_ENGINE_HPP

#include <string>
#include <string_view>
#include <vector>

namespace security_engine {

// Health vocabulary. Unknown is the default: an unchecked engine is never
// reported as healthy.
enum class HealthStatus { kHealthy, kUnknown, kDegraded, kUnavailable };

[[nodiscard]] std::string_view to_string(HealthStatus status) noexcept;

struct EngineHealth {
  HealthStatus status = HealthStatus::kUnknown;
  std::string detail;

  [[nodiscard]] bool is_healthy() const noexcept {
    return status == HealthStatus::kHealthy;
  }
};

// Static, non-sensitive description of this engine. Contains no paths and no
// configuration, so it is safe to return from a metadata endpoint.
struct EngineDescriptor {
  std::string name;
  std::string language = "cpp";
  std::string version;
  std::vector<std::string> capabilities;
};

// Describe this library.
[[nodiscard]] EngineDescriptor describe();

// Report health. PART 01 has no Python binding, so this honestly reports
// kUnavailable with that reason rather than claiming to be wired up.
[[nodiscard]] EngineHealth health();

}  // namespace security_engine

#endif  // SECURITY_ENGINE_ENGINE_HPP
