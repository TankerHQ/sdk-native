add_executable(test_tanker_streams
  test_peekableinputsource.cpp
  test_stream.cpp

  main.cpp
)

target_link_libraries(test_tanker_streams
  tankerstreams
  tankertesthelpers
  CONAN_PKG::catch2
)

add_test(NAME test_tanker_streams COMMAND test_tanker_streams)
