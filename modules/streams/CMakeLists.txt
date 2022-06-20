cmake_minimum_required(VERSION 3.4)

project(tankerstreams)

add_library(tankerstreams
  include/Tanker/Streams/BufferedStream.hpp
  include/Tanker/Streams/DecryptionStream.hpp
  include/Tanker/Streams/DecryptionStreamImpl.hpp
  include/Tanker/Streams/DecryptionStreamV4.hpp
  include/Tanker/Streams/DecryptionStreamV8.hpp
  include/Tanker/Streams/Detail/BufferedStreamImpl.hpp
  include/Tanker/Streams/EncryptionStream.hpp
  include/Tanker/Streams/EncryptionStreamImpl.hpp
  include/Tanker/Streams/EncryptionStreamV4.hpp
  include/Tanker/Streams/EncryptionStreamV8.hpp
  include/Tanker/Streams/InputSource.hpp
  include/Tanker/Streams/Header.hpp
  include/Tanker/Streams/Helpers.hpp
  include/Tanker/Streams/PeekableInputSource.hpp

  src/DecryptionStreamV4.cpp
  src/DecryptionStreamV8.cpp
  src/EncryptionStreamV4.cpp
  src/EncryptionStreamV8.cpp
  src/Header.cpp
  src/Helpers.cpp
  src/PeekableInputSource.cpp
)
target_include_directories(tankerstreams
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(tankerstreams
  PUBLIC
  tankercrypto
  tankerserialization
  tankertrustchain
  tankererrors

  tconcurrent::tconcurrent
  gsl-lite::gsl-lite
)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankerstreams
  EXPORT tankerstreams
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

add_subdirectory(test)
