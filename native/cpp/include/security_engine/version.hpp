// Version constants shared with core/version.py and the Rust crate.
#ifndef SECURITY_ENGINE_VERSION_HPP
#define SECURITY_ENGINE_VERSION_HPP

#include <string_view>

namespace security_engine {

// Library version, kept in step with CMakeLists.txt.
inline constexpr std::string_view kVersion = "0.1.0";

// Engine name as registered by services/engine_registry.py.
inline constexpr std::string_view kEngineName = "cpp_core";

// Major version of the shared JSON schemas.
inline constexpr std::string_view kSchemaVersion = "1";

}  // namespace security_engine

#endif  // SECURITY_ENGINE_VERSION_HPP
