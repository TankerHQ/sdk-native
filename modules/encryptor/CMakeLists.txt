cmake_minimum_required(VERSION 3.4)

project(tankerencryptor)

add_library(tankerencryptor STATIC
  include/Tanker/Encryptor.hpp
  include/Tanker/EncryptionMetadata.hpp
  include/Tanker/Encryptor/v2.hpp
  include/Tanker/Encryptor/v3.hpp
  include/Tanker/Encryptor/v4.hpp
  include/Tanker/Encryptor/v5.hpp
  include/Tanker/Encryptor/v6.hpp
  include/Tanker/Encryptor/v7.hpp
  include/Tanker/Encryptor/v8.hpp
  include/Tanker/Encryptor/v9.hpp
  include/Tanker/Encryptor/v10.hpp
  include/Tanker/Encryptor/v11.hpp

  src/Encryptor.cpp
  src/Encryptor/v2.cpp
  src/Encryptor/v3.cpp
  src/Encryptor/v4.cpp
  src/Encryptor/v5.cpp
  src/Encryptor/v6.cpp
  src/Encryptor/v7.cpp
  src/Encryptor/v8.cpp
  src/Encryptor/v9.cpp
  src/Encryptor/v10.cpp
  src/Encryptor/v11.cpp
)

target_include_directories(tankerencryptor
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerencryptor
  tankererrors
  tankerserialization
  tankertypes
  tankerstreams
  tankercrypto
  tankerformat
  tankerlog
  ttracer
  Boost
  tconcurrent::tconcurrent
  mgs::mgs
  gsl-lite::gsl-lite
  fmt::fmt
  nlohmann_json::nlohmann_json
  enum-flags::enum-flags
  range-v3::range-v3
)

install(TARGETS tankerencryptor
        EXPORT tankerencryptor
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        )

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
