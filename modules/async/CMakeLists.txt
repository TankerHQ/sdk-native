cmake_minimum_required(VERSION 3.4)

project(tanker_async)
include(GenerateExportHeader)

add_library(${PROJECT_NAME}
  include/ctanker/async.h
  include/ctanker/async/error.h
  include/ctanker/async/private/CFuture.hpp

  src/async.cpp
)

generate_export_header(${PROJECT_NAME}
  EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/ctanker/async/export.h
)

target_link_libraries(${PROJECT_NAME} PUBLIC tankererrors CONAN_PKG::tconcurrent)
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(
  DIRECTORY include DESTINATION .
  PATTERN "private" EXCLUDE
)
install(DIRECTORY ${CMAKE_BINARY_DIR}/include DESTINATION .)
