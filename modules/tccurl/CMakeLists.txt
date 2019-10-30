cmake_minimum_required(VERSION 3.4)

project(tccurl)

option(TANKER_BUILD_WITH_SSL "Tanker uses ssl" ON)

add_library(tccurl STATIC
  src/curl.cpp
  src/read_all.cpp
)

target_include_directories(tccurl
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tccurl
  tankercacerts
  tankererrors
  tankerlog

  # Keep libcurl *after* tconcurrent
  # There is a CMake bug where the -lws2_32 library
  # gets added at the wrong place on the command line,
  # - probably because tconcurrent and libcurl both
  # depend on libressl, which itself depends on
  # ws3_32 - and the link will fail if libcurl is placed 
  # before tconcurrent
  CONAN_PKG::tconcurrent
  CONAN_PKG::libcurl

)

install(TARGETS tccurl
  EXPORT tccurl
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if(TANKER_BUILD_WITH_SSL)
  target_compile_definitions(tccurl PUBLIC TANKER_BUILD_WITH_SSL)
  if (WIN32)
     target_link_libraries(tccurl crypt32)
  endif()
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
