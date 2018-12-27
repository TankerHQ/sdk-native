add_executable(bench_tanker
  bench.cpp
  main.cpp
)

target_link_libraries(bench_tanker
  tankercore_test
  tankertesthelpers
  CONAN_PKG::google-benchmark
)

target_compile_definitions(bench_tanker PRIVATE FMT_STRING_ALIAS)
add_test(NAME bench_tanker COMMAND bench_tanker)
