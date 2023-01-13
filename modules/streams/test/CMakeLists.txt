add_executable(test_tanker_streams
  test_peekableinputsource.cpp
  test_stream.cpp
  )


if(ANDROID)
  set_target_properties(test_tanker_streams PROPERTIES LINK_FLAGS "-llog")
endif()

target_link_libraries(test_tanker_streams
  tankerstreams
  tankertesthelpers
  Catch2::Catch2WithMain
)

add_test(NAME test_tanker_streams COMMAND test_tanker_streams)
