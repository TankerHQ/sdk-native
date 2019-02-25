add_executable(test_tanker_c
  config.cpp
  test.c
)

target_link_libraries(test_tanker_c ctanker tankertesthelpers)
add_test(NAME test_tanker_c COMMAND test_tanker_c)
