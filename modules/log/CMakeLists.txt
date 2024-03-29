cmake_minimum_required(VERSION 3.10)

project(Log)

add_library(tankerlog STATIC
  ${PROJECT_SOURCE_DIR}/include/Tanker/Log/Log.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Log/LogHandler.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Log/Record.hpp
  ${PROJECT_SOURCE_DIR}/include/Tanker/Log/Level.hpp

  src/Log.cpp
  src/LogHandler.cpp
)

target_include_directories(tankerlog
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerlog tankerconfig tankerformat fmt::fmt)

if(ANDROID)
  target_link_options(tankerlog PUBLIC "-llog")
endif()

install(DIRECTORY include DESTINATION .)

install(TARGETS tankerlog
  EXPORT tankerlog
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
