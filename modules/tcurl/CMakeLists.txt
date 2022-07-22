cmake_minimum_required(VERSION 3.4)

project(tcurl)

add_library(tcurl STATIC
    src/curl.cpp
    src/read_all.cpp

    include/tcurl.hpp
)

target_include_directories(tcurl
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tcurl

  tconcurrent::tconcurrent
  libcurl::libcurl
)

install(TARGETS tcurl
  EXPORT tcurl
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
