cmake_minimum_required(VERSION 3.10)

project(Format)

add_library(tankerformat STATIC

  include/Tanker/Format/Json.hpp
  include/Tanker/Format/Enum.hpp
  include/Tanker/Format/Width.hpp
  include/Tanker/Format/StringView.hpp

  src/Json.cpp
)

target_include_directories(tankerformat
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerformat PUBLIC fmt::fmt nlohmann_json::nlohmann_json)

install(DIRECTORY include DESTINATION .)
install(TARGETS tankerformat
  EXPORT tankerformat
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
