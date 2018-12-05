add_executable(test_gen
  test_generator.cpp
  main.cpp
)

target_include_directories(test_gen PRIVATE .)

target_link_libraries(test_gen generator tankertesthelpers CONAN_PKG::doctest)
