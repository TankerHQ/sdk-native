cmake_minimum_required(VERSION 3.10)

project(TankerCli)

add_executable(tcli
  main.cpp
)

target_link_libraries(tcli tankercore docopt.cpp::docopt.cpp mgs::mgs)
