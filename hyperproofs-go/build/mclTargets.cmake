# Generated by CMake

if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 2.8)
   message(FATAL_ERROR "CMake >= 2.8.0 required")
endif()
if(CMAKE_VERSION VERSION_LESS "2.8.3")
   message(FATAL_ERROR "CMake >= 2.8.3 required")
endif()
cmake_policy(PUSH)
cmake_policy(VERSION 2.8.3...3.24)
#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Protect against multiple inclusion, which would fail when already imported targets are added once more.
set(_cmake_targets_defined "")
set(_cmake_targets_not_defined "")
set(_cmake_expected_targets "")
foreach(_cmake_expected_target IN ITEMS mcl::mcl mcl::mcl_st mcl::mclbn256 mcl::mclbn384 mcl::mclbn384_256)
  list(APPEND _cmake_expected_targets "${_cmake_expected_target}")
  if(TARGET "${_cmake_expected_target}")
    list(APPEND _cmake_targets_defined "${_cmake_expected_target}")
  else()
    list(APPEND _cmake_targets_not_defined "${_cmake_expected_target}")
  endif()
endforeach()
unset(_cmake_expected_target)
if(_cmake_targets_defined STREQUAL _cmake_expected_targets)
  unset(_cmake_targets_defined)
  unset(_cmake_targets_not_defined)
  unset(_cmake_expected_targets)
  unset(CMAKE_IMPORT_FILE_VERSION)
  cmake_policy(POP)
  return()
endif()
if(NOT _cmake_targets_defined STREQUAL "")
  string(REPLACE ";" ", " _cmake_targets_defined_text "${_cmake_targets_defined}")
  string(REPLACE ";" ", " _cmake_targets_not_defined_text "${_cmake_targets_not_defined}")
  message(FATAL_ERROR "Some (but not all) targets in this export set were already defined.\nTargets Defined: ${_cmake_targets_defined_text}\nTargets not yet defined: ${_cmake_targets_not_defined_text}\n")
endif()
unset(_cmake_targets_defined)
unset(_cmake_targets_not_defined)
unset(_cmake_expected_targets)


# Create imported target mcl::mcl
add_library(mcl::mcl SHARED IMPORTED)

set_target_properties(mcl::mcl PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "MCL_NO_AUTOLINK;MCLBN_NO_AUTOLINK;NOMINMAX"
  INTERFACE_INCLUDE_DIRECTORIES "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/mcl/include"
  INTERFACE_LINK_LIBRARIES "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bint-x64-win.obj"
)

# Create imported target mcl::mcl_st
add_library(mcl::mcl_st STATIC IMPORTED)

set_target_properties(mcl::mcl_st PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "MCL_NO_AUTOLINK;MCLBN_NO_AUTOLINK;NOMINMAX"
  INTERFACE_INCLUDE_DIRECTORIES "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/mcl/include"
  INTERFACE_LINK_LIBRARIES "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bint-x64-win.obj"
)

# Create imported target mcl::mclbn256
add_library(mcl::mclbn256 SHARED IMPORTED)

set_target_properties(mcl::mclbn256 PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "MCL_NO_AUTOLINK;MCLBN_NO_AUTOLINK"
  INTERFACE_LINK_LIBRARIES "mcl::mcl"
)

# Create imported target mcl::mclbn384
add_library(mcl::mclbn384 SHARED IMPORTED)

set_target_properties(mcl::mclbn384 PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "MCL_NO_AUTOLINK;MCLBN_NO_AUTOLINK"
  INTERFACE_LINK_LIBRARIES "mcl::mcl"
)

# Create imported target mcl::mclbn384_256
add_library(mcl::mclbn384_256 SHARED IMPORTED)

set_target_properties(mcl::mclbn384_256 PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "MCL_NO_AUTOLINK;MCLBN_NO_AUTOLINK"
  INTERFACE_LINK_LIBRARIES "mcl::mcl"
)

# Import target "mcl::mcl" for configuration "Debug"
set_property(TARGET mcl::mcl APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mcl::mcl PROPERTIES
  IMPORTED_IMPLIB_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Debug/mcl.lib"
  IMPORTED_LOCATION_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Debug/mcl.dll"
  )

# Import target "mcl::mcl_st" for configuration "Debug"
set_property(TARGET mcl::mcl_st APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mcl::mcl_st PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Debug/mcl.lib"
  )

# Import target "mcl::mclbn256" for configuration "Debug"
set_property(TARGET mcl::mclbn256 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mcl::mclbn256 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Debug/mclbn256.lib"
  IMPORTED_LOCATION_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Debug/mclbn256.dll"
  )

# Import target "mcl::mclbn384" for configuration "Debug"
set_property(TARGET mcl::mclbn384 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mcl::mclbn384 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Debug/mclbn384.lib"
  IMPORTED_LOCATION_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Debug/mclbn384.dll"
  )

# Import target "mcl::mclbn384_256" for configuration "Debug"
set_property(TARGET mcl::mclbn384_256 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mcl::mclbn384_256 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Debug/mclbn384_256.lib"
  IMPORTED_LOCATION_DEBUG "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Debug/mclbn384_256.dll"
  )

# Import target "mcl::mcl" for configuration "Release"
set_property(TARGET mcl::mcl APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(mcl::mcl PROPERTIES
  IMPORTED_IMPLIB_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Release/mcl.lib"
  IMPORTED_LOCATION_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Release/mcl.dll"
  )

# Import target "mcl::mcl_st" for configuration "Release"
set_property(TARGET mcl::mcl_st APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(mcl::mcl_st PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Release/mcl.lib"
  )

# Import target "mcl::mclbn256" for configuration "Release"
set_property(TARGET mcl::mclbn256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(mcl::mclbn256 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Release/mclbn256.lib"
  IMPORTED_LOCATION_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Release/mclbn256.dll"
  )

# Import target "mcl::mclbn384" for configuration "Release"
set_property(TARGET mcl::mclbn384 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(mcl::mclbn384 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Release/mclbn384.lib"
  IMPORTED_LOCATION_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Release/mclbn384.dll"
  )

# Import target "mcl::mclbn384_256" for configuration "Release"
set_property(TARGET mcl::mclbn384_256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(mcl::mclbn384_256 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/Release/mclbn384_256.lib"
  IMPORTED_LOCATION_RELEASE "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/Release/mclbn384_256.dll"
  )

# Import target "mcl::mcl" for configuration "MinSizeRel"
set_property(TARGET mcl::mcl APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(mcl::mcl PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/MinSizeRel/mcl.lib"
  IMPORTED_LOCATION_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/MinSizeRel/mcl.dll"
  )

# Import target "mcl::mcl_st" for configuration "MinSizeRel"
set_property(TARGET mcl::mcl_st APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(mcl::mcl_st PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_MINSIZEREL "CXX"
  IMPORTED_LOCATION_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/MinSizeRel/mcl.lib"
  )

# Import target "mcl::mclbn256" for configuration "MinSizeRel"
set_property(TARGET mcl::mclbn256 APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(mcl::mclbn256 PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/MinSizeRel/mclbn256.lib"
  IMPORTED_LOCATION_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/MinSizeRel/mclbn256.dll"
  )

# Import target "mcl::mclbn384" for configuration "MinSizeRel"
set_property(TARGET mcl::mclbn384 APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(mcl::mclbn384 PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/MinSizeRel/mclbn384.lib"
  IMPORTED_LOCATION_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/MinSizeRel/mclbn384.dll"
  )

# Import target "mcl::mclbn384_256" for configuration "MinSizeRel"
set_property(TARGET mcl::mclbn384_256 APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(mcl::mclbn384_256 PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/MinSizeRel/mclbn384_256.lib"
  IMPORTED_LOCATION_MINSIZEREL "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/MinSizeRel/mclbn384_256.dll"
  )

# Import target "mcl::mcl" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mcl APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mcl PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/RelWithDebInfo/mcl.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/RelWithDebInfo/mcl.dll"
  )

# Import target "mcl::mcl_st" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mcl_st APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mcl_st PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "CXX"
  IMPORTED_LOCATION_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/RelWithDebInfo/mcl.lib"
  )

# Import target "mcl::mclbn256" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn256 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/RelWithDebInfo/mclbn256.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/RelWithDebInfo/mclbn256.dll"
  )

# Import target "mcl::mclbn384" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn384 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn384 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/RelWithDebInfo/mclbn384.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/RelWithDebInfo/mclbn384.dll"
  )

# Import target "mcl::mclbn384_256" for configuration "RelWithDebInfo"
set_property(TARGET mcl::mclbn384_256 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(mcl::mclbn384_256 PROPERTIES
  IMPORTED_IMPLIB_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/lib/RelWithDebInfo/mclbn384_256.lib"
  IMPORTED_LOCATION_RELWITHDEBINFO "C:/Users/parti/summer_projects/ToR/Vector Commitment/rollup_project/hyperproofs-go/build/bin/RelWithDebInfo/mclbn384_256.dll"
  )

# This file does not depend on other imported targets which have
# been exported from the same project but in a separate export set.

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)
