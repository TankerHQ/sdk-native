cmake_minimum_required(VERSION 3.5)
project(PackageTest)

find_package(tanker)

add_executable(example example.c)
target_link_libraries(example tanker::tanker)
