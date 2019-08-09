cmake_minimum_required(VERSION 3.4)

project(tanker_fake-authentication-c)
include(GenerateExportHeader)

add_library(tanker_fake-authentication-c STATIC
  include/ctanker/fakeauthentication.h

  src/fakeauthentication.cpp
)

generate_export_header(tanker_fake-authentication-c
  EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/ctanker/fakeauthentication/export.h
)

target_include_directories(tanker_fake-authentication-c
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tanker_fake-authentication-c PUBLIC
  tankerfakeauthentication
  tanker_async
  tankererrors
)

install(TARGETS tanker_fake-authentication-c
  EXPORT tanker_fake-authentication-c
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include DESTINATION .)
install(DIRECTORY ${CMAKE_BINARY_DIR}/include DESTINATION .)
