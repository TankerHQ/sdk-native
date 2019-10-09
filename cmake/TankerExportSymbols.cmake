macro(tanker_export_symbols target)
  if (APPLE)
    set_target_properties(${target} PROPERTIES
      LINK_FLAGS "-Wl,-exported_symbols_list ${CMAKE_CURRENT_LIST_DIR}/exported_symbols.sym")
  elseif (UNIX OR MINGW)
    set_target_properties(${target} PROPERTIES
      LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_LIST_DIR}/exported_symbols.ld")
  elseif (MSVC)
    set_target_properties(${target} PROPERTIES
      LINK_FLAGS "/DEF:${CMAKE_CURRENT_LIST_DIR}/exported_symbols.def")
  else ()
    message(FATAL_ERROR "No exported symbols file for this platform")
  endif()
endmacro()
