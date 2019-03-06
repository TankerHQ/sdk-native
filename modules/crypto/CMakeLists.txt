cmake_minimum_required(VERSION 3.4)

project(tankercrypto)

add_library(tankercrypto STATIC
    src/Crypto.cpp
    src/JsonFormat.cpp

    include/Tanker/Crypto/Crypto.hpp
    include/Tanker/Crypto/Types.hpp
    include/Tanker/Crypto/base64.hpp
    include/Tanker/Crypto/Traits.hpp
    include/Tanker/Crypto/KeyFormat.hpp
    include/Tanker/Crypto/JsonFormat.hpp
)

target_include_directories(tankercrypto
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankercrypto tankerserialization CONAN_PKG::libsodium CONAN_PKG::cppcodec CONAN_PKG::gsl-lite CONAN_PKG::jsonformoderncpp CONAN_PKG::fmt)

install(TARGETS tankercrypto
  EXPORT tankercrypto
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
