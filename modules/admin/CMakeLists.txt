cmake_minimum_required(VERSION 3.4)

project(Admin)

add_library(tankeradmin STATIC
  include/Tanker/Admin/Client.hpp

  src/Client.cpp
)

target_include_directories(tankeradmin
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankeradmin
  tankertypes
  tankererrors
  tankercacerts
  tankercore
  ttracer
  tcurl

  gsl-lite::gsl-lite
  mgs::mgs
  tconcurrent::tconcurrent
  nlohmann_json::nlohmann_json
  libcurl::libcurl
  )

install(DIRECTORY include DESTINATION .)
install(TARGETS tankeradmin
  EXPORT tankeradmin
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
