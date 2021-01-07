cmake_minimum_required(VERSION 3.4)

project(bench)

add_executable(bench_tanker
  BenchHelpers.cpp
  main.cpp

  encrypt.cpp
  groups.cpp
  session.cpp
)

target_link_libraries(bench_tanker
  tankercore
  tankerfunctionalhelpers
  tankertesthelpers
  CONAN_PKG::benchmark
)
