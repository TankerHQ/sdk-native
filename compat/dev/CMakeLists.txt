cmake_minimum_required(VERSION 3.5)
project(compat-v2.0.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

add_executable(compat main.cpp)
target_link_libraries(compat CONAN_PKG::docopt.cpp CONAN_PKG::tanker CONAN_PKG::cppcodec)
