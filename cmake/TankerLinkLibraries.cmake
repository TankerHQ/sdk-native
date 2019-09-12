function(tanker_link_libraries target)
  if (APPLE)
    set(_whole_archive "-Wl,-force_load")
  elseif (UNIX) # this means linux, including android
    set(_whole_archive "-Wl,--whole-archive")
    set(_no_whole_archive "-Wl,--no-whole-archive")
  endif()

  cmake_parse_arguments(TANKER "" "" EMBED_LIBS ${ARGN})

  message(STATUS "${target} will embed symbols from: ${TANKER_EMBED_LIBS}")
  target_link_libraries(${target} ${TANKER_UNPARSED_ARGUMENTS} ${_whole_archive} ${TANKER_EMBED_LIBS} ${_no_whole_archive})
endfunction()
