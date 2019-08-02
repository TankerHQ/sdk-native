cmake_minimum_required(VERSION 3.4)

project(TankerSDK-CACerts)

option(TANKER_BUILD_WITH_SSL "Tanker uses ssl" ON)
option(TANKER_EMBED_CERTIFICATES "Tanker embeds root certificates" OFF)

if (WIN32 AND TANKER_EMBED_CERTIFICATES)
  message(FATAL_ERROR "can't embed certificates on win32, not implemented")
endif()
if (NOT TANKER_BUILD_WITH_SSL AND TANKER_EMBED_CERTIFICATES)
  message(FATAL_ERROR "can't embed certificates when building without SSL support")
endif()

if (TANKER_EMBED_CERTIFICATES)
  enable_language(ASM)
  set(CERTIFICATES_SRC
    src/ca_certificates.s
  )
endif()

add_library(tankercacerts STATIC
  include/Tanker/InitSsl.hpp
  src/InitSsl.cpp

  ${CERTIFICATES_SRC}
)
target_include_directories(tankercacerts PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(tankercacerts
  tankerlog
)

if(TANKER_EMBED_CERTIFICATES)
  target_compile_definitions(tankercacerts PUBLIC TANKER_EMBED_CERTIFICATES)
endif()
if(TANKER_BUILD_WITH_SSL)
  target_compile_definitions(tankercacerts PUBLIC TANKER_BUILD_WITH_SSL)
  if (WIN32)
     target_link_libraries(tankercacerts crypt32)
  endif()

  target_link_libraries(tankercacerts
    CONAN_PKG::LibreSSL
  )
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # cmake gives a ton of unused arguments to clang to compile ASM
  target_compile_options(tankercacerts PRIVATE "-Wno-unused-command-line-argument")
endif()

install(TARGETS tankercacerts
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
