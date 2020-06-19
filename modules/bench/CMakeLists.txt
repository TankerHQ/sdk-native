cmake_minimum_required(VERSION 3.4)

project(bench)

add_executable(bench_tanker
  bench.cpp
  main.cpp
)

target_link_libraries(bench_tanker
  tankercore
  tankerfunctionalhelpers
  tankertesthelpers
  CONAN_PKG::benchmark
)

add_test(NAME bench_tanker COMMAND bench_tanker)
