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
  CONAN_PKG::libcurl
  CONAN_PKG::tconcurrent
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
     target_link_libraries(tccurl crypt32 cryptui)
  endif()
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()
