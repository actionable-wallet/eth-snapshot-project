#----------------------------------------------------------------
# Generated CMake target import file for configuration "RelWithDebInfo".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "mcl::mcl" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mcl APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mcl PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mcl.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mcl.dll"
  )

list(APPEND _cmake_import_check_targets mcl::mcl )
list(APPEND _cmake_import_check_files_for_mcl::mcl "${_IMPORT_PREFIX}/lib/mcl.lib" "${_IMPORT_PREFIX}/lib/mcl.dll" )

# Import target "mcl::mcl_st" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mcl_st APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mcl_st PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "CXX"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mcl.lib"
  )

list(APPEND _cmake_import_check_targets mcl::mcl_st )
list(APPEND _cmake_import_check_files_for_mcl::mcl_st "${_IMPORT_PREFIX}/lib/mcl.lib" )

# Import target "mcl::mclbn256" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn256 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn256.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn256.dll"
  )

list(APPEND _cmake_import_check_targets mcl::mclbn256 )
list(APPEND _cmake_import_check_files_for_mcl::mclbn256 "${_IMPORT_PREFIX}/lib/mclbn256.lib" "${_IMPORT_PREFIX}/lib/mclbn256.dll" )

# Import target "mcl::mclbn384" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn384 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn384 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn384.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn384.dll"
  )

list(APPEND _cmake_import_check_targets mcl::mclbn384 )
list(APPEND _cmake_import_check_files_for_mcl::mclbn384 "${_IMPORT_PREFIX}/lib/mclbn384.lib" "${_IMPORT_PREFIX}/lib/mclbn384.dll" )

# Import target "mcl::mclbn384_256" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn384_256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn384_256 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn384_256.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/mclbn384_256.dll"
  )

list(APPEND _cmake_import_check_targets mcl::mclbn384_256 )
list(APPEND _cmake_import_check_files_for_mcl::mclbn384_256 "${_IMPORT_PREFIX}/lib/mclbn384_256.lib" "${_IMPORT_PREFIX}/lib/mclbn384_256.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
