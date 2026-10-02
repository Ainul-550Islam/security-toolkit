#include "security_engine/engine.hpp"

#include <string>

#include "security_engine/version.hpp"

namespace security_engine {

std::string_view to_string(HealthStatus status) noexcept {
  switch (status) {
    case HealthStatus::kHealthy:
      return "healthy";
    case HealthStatus::kDegraded:
      return "degraded";
    case HealthStatus::kUnavailable:
      return "unavailable";
    case HealthStatus::kUnknown:
      break;
  }
  return "unknown";
}

EngineDescriptor describe() {
  EngineDescriptor descriptor;
  descriptor.name = std::string(kEngineName);
  descriptor.language = "cpp";
  descriptor.version = std::string(kVersion);
  descriptor.capabilities = {"buffer_inspect"};
  return descriptor;
}

EngineHealth health() {
  EngineHealth result;
  // Honest status: the library builds and its primitives work, but no FFI
  // bridge to Python exists in PART 01, so it cannot serve requests.
  result.status = HealthStatus::kUnavailable;
  result.detail = "native binding not loaded (library builds; no FFI bridge yet)";
  return result;
}

}  // namespace security_engine
