cmake_minimum_required(VERSION 3.4)

project(TankerCli)

add_executable(tcli
  main.cpp
)

target_link_libraries(tcli tankercore CONAN_PKG::docopt.cpp)
