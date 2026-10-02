cmake_minimum_required(VERSION 3.16)

project(security_engine
        VERSION 0.1.0
        DESCRIPTION "C++ foundation library for the security toolkit"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
endif()

# Hardening. These are defaults, not opt-ins: a security library compiled
# without stack protection or FORTIFY_SOURCE is a poor advertisement.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(
      -Wall -Wextra -Wpedantic
      -Wconversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast
      -Wcast-align -Wunused -Woverloaded-virtual -Wnull-dereference
      -Wdouble-promotion -Wformat=2
      -fstack-protector-strong
      -D_FORTIFY_SOURCE=2
  )
  add_link_options(-Wl,-z,relro -Wl,-z,now)
endif()

add_library(security_engine STATIC
    src/buffer.cpp
    src/engine.cpp
)

target_include_directories(security_engine
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

set_target_properties(security_engine PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
)

# Self-test executable. It is the C++ validation step: `cmake --build` then
# run it, so the library is proven to work rather than merely to compile.
add_executable(security_engine_tests tests/test_main.cpp)
target_link_libraries(security_engine_tests PRIVATE security_engine)

enable_testing()
add_test(NAME security_engine_tests COMMAND security_engine_tests)
