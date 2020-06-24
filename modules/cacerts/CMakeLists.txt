cmake_minimum_required(VERSION 3.4)

project(TankerSDK-CACerts)

option(TANKER_EMBED_CERTIFICATES "Tanker embeds root certificates" OFF)

if (WIN32 AND TANKER_EMBED_CERTIFICATES)
  message(FATAL_ERROR "can't embed certificates on win32, not implemented")
endif()

if (TANKER_EMBED_CERTIFICATES)
  enable_language(ASM)
  if (CMAKE_SYSTEM_NAME MATCHES Darwin)
    set(CMAKE_ASM_FLAGS "${CMAKE_CXX_FLAGS} -x assembler-with-cpp")
  endif()
  set(CERTIFICATES_SRC
    src/ca_certificates.s
  )
endif()

add_library(tankercacerts STATIC
  include/Tanker/Cacerts/InitSsl.hpp
  src/InitSsl.cpp

  ${CERTIFICATES_SRC}
)

target_include_directories(tankercacerts PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(tankercacerts
  tankerlog
  tankererrors
  CONAN_PKG::boost
  CONAN_PKG::libressl
)

target_compile_definitions(tankercacerts PUBLIC TANKER_BUILD_WITH_SSL)
if(TANKER_EMBED_CERTIFICATES)
  target_compile_definitions(tankercacerts PUBLIC TANKER_EMBED_CERTIFICATES)
endif()

if (WIN32)
   target_link_libraries(tankercacerts crypt32)
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
