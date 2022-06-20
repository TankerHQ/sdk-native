cmake_minimum_required(VERSION 3.4)

project(TankerSDK-Trace)

if(NOT WITH_TRACER)

  add_library(ttracer INTERFACE)

  target_include_directories(ttracer
    INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  )

else()

  ## You need to have lttng installed on your system for these to work
  ## Please refer to the tracer/README.md for installation
  ## Sadly, lttng dos not provide a find_package()

  add_library(ttracer
    include/Tanker/Tracer/ScopeTimer.hpp
    include/Tanker/Tracer/ScopeDuration.hpp
    include/Tanker/Tracer/FuncTracer.hpp

    src/ScopeTimer.cpp
    src/ScopeDuration.cpp
    src/FuncTracer.cpp
  )

  target_sources(
    ttracer

    PRIVATE
    src/ttracer.h
    src/TTracer.hpp

    src/TTracer.cpp
   )

  target_compile_definitions(ttracer PUBLIC TANKER_ENABLE_TRACER)

  target_include_directories(ttracer
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    src
  )

  target_link_libraries(ttracer
    tconcurrent::tconcurrent
    lttng-ust
    dl
  )

endif()
