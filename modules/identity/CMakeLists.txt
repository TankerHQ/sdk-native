cmake_minimum_required(VERSION 3.4)

project(tankeridentity)

add_library(tankeridentity STATIC
  include/Tanker/Identity/UserToken.hpp
  include/Tanker/Identity/Delegation.hpp
  include/Tanker/Identity/Utils.hpp
  include/Tanker/Identity/SecretPermanentIdentity.hpp
  include/Tanker/Identity/SecretProvisionalIdentity.hpp
  include/Tanker/Identity/PublicPermanentIdentity.hpp
  include/Tanker/Identity/PublicProvisionalIdentity.hpp
  include/Tanker/Identity/PublicIdentity.hpp
  include/Tanker/Identity/SecretIdentity.hpp
  include/Tanker/Identity/Extract.hpp
  include/Tanker/Identity/TargetType.hpp
  include/Tanker/Identity/Errors/Errc.hpp
  include/Tanker/Identity/Errors/ErrcCategory.hpp

  src/UserToken.cpp
  src/Extract.cpp
  src/Delegation.cpp
  src/Utils.cpp
  src/SecretPermanentIdentity.cpp
  src/SecretProvisionalIdentity.cpp
  src/PublicPermanentIdentity.cpp
  src/PublicProvisionalIdentity.cpp
  src/PublicIdentity.cpp
  src/SecretIdentity.cpp
  src/TargetType.cpp
  src/Errors/Errc.cpp
  src/Errors/ErrcCategory.cpp
)

target_include_directories(tankeridentity
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(
  tankeridentity
  tankertrustchain
  tankertypes
  tankercrypto
  tankererrors

  CONAN_PKG::jsonformoderncpp
  CONAN_PKG::gsl-lite
  CONAN_PKG::cppcodec
)

install(TARGETS tankeridentity
  EXPORT tankeridentity
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
