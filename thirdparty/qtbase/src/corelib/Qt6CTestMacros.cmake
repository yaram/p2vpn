#
#  W A R N I N G
#  -------------
#
# This file is not part of the Qt API.  It exists purely as an
# implementation detail.  This file, and its contents may change from version to
# version without notice, or even be removed.
#
# We mean it.

message("CMAKE_VERSION: ${CMAKE_VERSION}")
message("CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
message("CMAKE_MODULES_UNDER_TEST: ${CMAKE_MODULES_UNDER_TEST}")
foreach(_mod ${CMAKE_MODULES_UNDER_TEST})
    message("CMAKE_${_mod}_MODULE_MAJOR_VERSION: ${CMAKE_${_mod}_MODULE_MAJOR_VERSION}")
    message("CMAKE_${_mod}_MODULE_MINOR_VERSION: ${CMAKE_${_mod}_MODULE_MINOR_VERSION}")
    message("CMAKE_${_mod}_MODULE_PATCH_VERSION: ${CMAKE_${_mod}_MODULE_PATCH_VERSION}")
endforeach()

set(BUILD_OPTIONS_LIST)

if (CMAKE_C_COMPILER AND NOT CMAKE_CROSSCOMPILING)
  list(APPEND BUILD_OPTIONS_LIST "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()

if (CMAKE_CXX_COMPILER AND NOT CMAKE_CROSSCOMPILING)
  list(APPEND BUILD_OPTIONS_LIST "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if (CMAKE_BUILD_TYPE)
  list(APPEND BUILD_OPTIONS_LIST "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
endif()

if (CMAKE_TOOLCHAIN_FILE)
  file(TO_CMAKE_PATH "${CMAKE_TOOLCHAIN_FILE}" _CMAKE_TOOLCHAIN_FILE)
  list(APPEND BUILD_OPTIONS_LIST "-DCMAKE_TOOLCHAIN_FILE=${_CMAKE_TOOLCHAIN_FILE}")
endif()

if (CMAKE_VERBOSE_MAKEFILE)
  list(APPEND BUILD_OPTIONS_LIST "-DCMAKE_VERBOSE_MAKEFILE=1")
endif()

if (NO_GUI)
  list(APPEND BUILD_OPTIONS_LIST "-DNO_GUI=True")
endif()
if (NO_WIDGETS)
  list(APPEND BUILD_OPTIONS_LIST "-DNO_WIDGETS=True")
endif()
if (NO_DBUS)
  list(APPEND BUILD_OPTIONS_LIST "-DNO_DBUS=True")
endif()

if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    list(LENGTH CMAKE_OSX_ARCHITECTURES osx_arch_count)

    # When Qt is built as universal config (macOS or iOS), force CMake build tests to build one
    # architecture instead of all of them, because the build machine that builds the cmake tests
    # might not have a universal SDK installed.
    if(osx_arch_count GREATER 1)
        list(APPEND BUILD_OPTIONS_LIST "-DQT_FORCE_SINGLE_QT_OSX_ARCHITECTURE=ON")
    endif()
endif()

foreach(module ${CMAKE_MODULES_UNDER_TEST})
    list(APPEND BUILD_OPTIONS_LIST
        "-DCMAKE_${module}_MODULE_MAJOR_VERSION=${CMAKE_${module}_MODULE_MAJOR_VERSION}"
        "-DCMAKE_${module}_MODULE_MINOR_VERSION=${CMAKE_${module}_MODULE_MINOR_VERSION}"
        "-DCMAKE_${module}_MODULE_PATCH_VERSION=${CMAKE_${module}_MODULE_PATCH_VERSION}"
    )
endforeach()

function(_qt_internal_set_up_test_run_environment testname)
    # This is copy-pasted from qt_add_test and adapted to the standalone project case.
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(QT_PATH_SEPARATOR "\\;")
    else()
        set(QT_PATH_SEPARATOR ":")
    endif()

    if(NOT INSTALL_BINDIR)
        set(INSTALL_BINDIR bin)
    endif()

    if(NOT INSTALL_PLUGINSDIR)
        set(INSTALL_PLUGINSDIR "plugins")
    endif()

    set(install_prefixes "")
    if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(install_prefixes "${CMAKE_INSTALL_PREFIX}")
    endif()

    # If part of Qt build or standalone tests, use the build internals install prefix.
    # If the tests are configured as a separate project, use the Qt6 package provided install
    # prefix.
    if(QT_BUILD_INTERNALS_RELOCATABLE_INSTALL_PREFIX)
        list(APPEND install_prefixes "${QT_BUILD_INTERNALS_RELOCATABLE_INSTALL_PREFIX}")
    else()
        list(APPEND install_prefixes "${QT6_INSTALL_PREFIX}")
    endif()

    set(test_env_path "PATH=${CMAKE_CURRENT_BINARY_DIR}")
    foreach(install_prefix ${install_prefixes})
        set(test_env_path "${test_env_path}${QT_PATH_SEPARATOR}${install_prefix}/${INSTALL_BINDIR}")
    endforeach()
    set(test_env_path "${test_env_path}${QT_PATH_SEPARATOR}$ENV{PATH}")
    string(REPLACE ";" "\;" test_env_path "${test_env_path}")
    set_property(TEST "${testname}" APPEND PROPERTY ENVIRONMENT "${test_env_path}")
    set_property(TEST "${testname}" APPEND PROPERTY ENVIRONMENT "QT_TEST_RUNNING_IN_CTEST=1")

    # Add the install prefix to list of plugin paths when doing a prefix build
    if(NOT QT_INSTALL_DIR)
        foreach(install_prefix ${install_prefixes})
            list(APPEND plugin_paths "${install_prefix}/${INSTALL_PLUGINSDIR}")
        endforeach()
    endif()

    #TODO: Collect all paths from known repositories when performing a super
    # build.
    list(APPEND plugin_paths "${PROJECT_BINARY_DIR}/${INSTALL_PLUGINSDIR}")
    list(JOIN plugin_paths "${QT_PATH_SEPARATOR}" plugin_paths_joined)
    set_property(TEST "${testname}"
                 APPEND PROPERTY ENVIRONMENT "QT_PLUGIN_PATH=${plugin_paths_joined}")

endfunction()

# Checks if the test project can be built successfully. Arguments:
#
# SIMULATE_IN_SOURCE: If the option is specified, the function copies sources of the tests to the
#                     CMAKE_CURRENT_BINARY_DIR directory, creates internal build directory in the
#                     copied sources and uses this directory to build and test the project.
#                     This makes possible to have relative paths to the source files in the
#                     generated ninja rules.
#
# BUILD_DIR: A custom build dir relative to the calling project CMAKE_CURRENT_BINARY_DIR.
#            Useful when configuring the same test project with different options in separate
#            build dirs.
#
# BINARY: Path to the test artifact that will be executed after the build is complete. If a
#         relative path is specified, it will be counted from the build directory.
#         Can also be passed a random executable to be found in PATH, like 'ctest'.
#
# BINARY_ARGS: Additional arguments to pass to the BINARY.
#
# TESTNAME: a custom test name to use instead of the one derived from the source directory name
#
# BUILD_OPTIONS: a list of -D style CMake definitions to pass to ctest's --build-options (which
#                are ultimately passed to the CMake invocation of the test project)
macro(_qt_internal_test_expect_pass _dir)
  set(_test_option_args
      SIMULATE_IN_SOURCE
  )
  set(_test_single_args
      BINARY
      TESTNAME
      BUILD_DIR
  )
  set(_test_multi_args
      BUILD_OPTIONS
      BINARY_ARGS
  )
  cmake_parse_arguments(_ARGS
      "${_test_option_args}"
      "${_test_single_args}"
      "${_test_multi_args}"
      ${ARGN}
  )
  if(_ARGS_TESTNAME)
      set(testname "${_ARGS_TESTNAME}")
  else()
      string(REPLACE "(" "_" testname "${_dir}")
      string(REPLACE ")" "_" testname "${testname}")
      string(REPLACE "/" "_" testname "${testname}")
  endif()

    set(__expect_pass_prefixes "${CMAKE_PREFIX_PATH}")
    string(REPLACE ";" "\;" __expect_pass_prefixes "${__expect_pass_prefixes}")

    set(__expect_pass_build_dir "${CMAKE_CURRENT_BINARY_DIR}/${_dir}")
    if(_ARGS_BUILD_DIR)
        set(__expect_pass_build_dir "${CMAKE_CURRENT_BINARY_DIR}/${_ARGS_BUILD_DIR}")
    endif()

    set(__expect_pass_source_dir "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}")
    if(_ARGS_SIMULATE_IN_SOURCE)
        set(__expect_pass_in_source_build_dir "${CMAKE_CURRENT_BINARY_DIR}/in_source")
        set(__expect_pass_build_dir "${__expect_pass_in_source_build_dir}/${_dir}/build")
        set(__expect_pass_source_dir "${__expect_pass_in_source_build_dir}/${_dir}")

        unset(__expect_pass_in_source_build_dir)
    endif()

    if(_ARGS_BINARY AND NOT IS_ABSOLUTE "${_ARGS_BINARY}")
        set(_ARGS_BINARY "${__expect_pass_build_dir}/${_ARGS_BINARY}")
    endif()

    if(_ARGS_SIMULATE_IN_SOURCE)
      add_test(NAME ${testname}_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${__expect_pass_source_dir}"
      )
      set_tests_properties(${testname}_cleanup PROPERTIES
          FIXTURES_SETUP "${testname}SIMULATE_IN_SOURCE_FIXTURE"
      )
      add_test(${testname}_copy_sources ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}" "${__expect_pass_source_dir}"
      )
      set_tests_properties(${testname}_copy_sources PROPERTIES
          FIXTURES_SETUP "${testname}SIMULATE_IN_SOURCE_FIXTURE"
          DEPENDS ${testname}_cleanup
      )
    endif()

    set(ctest_command_args
        --build-and-test
        "${__expect_pass_source_dir}"
        "${__expect_pass_build_dir}"
        --build-config "${CMAKE_BUILD_TYPE}"
        --build-generator "${CMAKE_GENERATOR}"
        --build-makeprogram "${CMAKE_MAKE_PROGRAM}"
        --build-project "${_dir}"
        --build-options "-DCMAKE_PREFIX_PATH=${__expect_pass_prefixes}" ${BUILD_OPTIONS_LIST}
                        ${_ARGS_BUILD_OPTIONS}
        --test-command ${_ARGS_BINARY} ${_ARGS_BINARY_ARGS}
    )
    add_test(${testname} ${CMAKE_CTEST_COMMAND} ${ctest_command_args})
    if(_ARGS_SIMULATE_IN_SOURCE)
      set_tests_properties(${testname} PROPERTIES
          FIXTURES_REQUIRED "${testname}SIMULATE_IN_SOURCE_FIXTURE")
    endif()

    if(_ARGS_BINARY)
        _qt_internal_set_up_test_run_environment("${testname}")
    endif()

    unset(__expect_pass_source_dir)
    unset(__expect_pass_build_dir)
    unset(__expect_pass_prefixes)
endmacro()

# Checks if the build of the test project fails.
# This test passes if the test project fails either at the
# configuring or build steps.
# Arguments: See _qt_internal_test_expect_pass
macro(_qt_internal_test_expect_fail)
  _qt_internal_test_expect_pass(${ARGV})
  set_tests_properties(${testname} PROPERTIES WILL_FAIL TRUE)
endmacro()

# Checks if the build of the test project fails.
# This test passes only if the test project fails at the build step,
# but not at the configuring step.
macro(_qt_internal_test_expect_build_fail _dir)
  string(REPLACE "(" "_" testname "${_dir}")
  string(REPLACE ")" "_" testname "${testname}")
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}")

  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}/${_dir}/FindPackageHints.cmake"
      "set(Qt6Tests_PREFIX_PATH \"${CMAKE_PREFIX_PATH}\")
list(APPEND CMAKE_PREFIX_PATH \"${CMAKE_PREFIX_PATH}\")
")

  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}/CMakeLists.txt"
    "
      cmake_minimum_required(VERSION 3.14)
      project(${_dir})

      try_compile(Result \${CMAKE_CURRENT_BINARY_DIR}/${_dir}
          \${CMAKE_CURRENT_SOURCE_DIR}/${_dir}
          ${_dir}
          OUTPUT_VARIABLE Out
      )
      message(\"\${Out}\")
      if (Result)
        message(SEND_ERROR \"Succeeded build which should fail\")
      endif()
      "
  )
  add_test(${testname} ${CMAKE_CTEST_COMMAND}
    --build-and-test
    "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}"
    "${CMAKE_CURRENT_BINARY_DIR}/failbuild/${_dir}/build"
    --build-config "${CMAKE_BUILD_TYPE}"
    --build-generator "${CMAKE_GENERATOR}"
    --build-makeprogram "${CMAKE_MAKE_PROGRAM}"
    --build-project "${_dir}"
    --build-options "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}" ${BUILD_OPTIONS_LIST}
  )
endmacro()

function(_qt_internal_test_module_includes)

  set(all_args ${ARGN})
  set(packages_string "")
  set(libraries_string "")

  foreach(_package ${Qt6_MODULE_TEST_DEPENDS})
    set(packages_string
      "
      ${packages_string}
      find_package(Qt6${_package} 6.0.0 REQUIRED)
      "
    )
  endforeach()

  while(all_args)
    list(GET all_args 0 qtmodule)
    list(REMOVE_AT all_args 0 1)

    set(CMAKE_MODULE_VERSION ${CMAKE_${qtmodule}_MODULE_MAJOR_VERSION}.${CMAKE_${qtmodule}_MODULE_MINOR_VERSION}.${CMAKE_${qtmodule}_MODULE_PATCH_VERSION} )

    set(packages_string
      "${packages_string}
      find_package(Qt6${qtmodule} 6.0.0 REQUIRED)\n")

    list(FIND CMAKE_MODULES_UNDER_TEST ${qtmodule} _findIndex)
    if (NOT _findIndex STREQUAL -1)
        set(packages_string
          "${packages_string}
          if(NOT \"\${Qt6${qtmodule}_VERSION}\" VERSION_EQUAL ${CMAKE_MODULE_VERSION})
            message(SEND_ERROR \"Qt6${qtmodule}_VERSION variable was not ${CMAKE_MODULE_VERSION}. Got \${Qt6${qtmodule}_VERSION} instead.\")
          endif()
          if(NOT \"\${Qt6${qtmodule}_VERSION_MAJOR}\" VERSION_EQUAL ${CMAKE_${qtmodule}_MODULE_MAJOR_VERSION})
            message(SEND_ERROR \"Qt6${qtmodule}_VERSION_MAJOR variable was not ${CMAKE_${qtmodule}_MODULE_MAJOR_VERSION}. Got \${Qt6${qtmodule}_VERSION_MAJOR} instead.\")
          endif()
          if(NOT \"\${Qt6${qtmodule}_VERSION_MINOR}\" VERSION_EQUAL ${CMAKE_${qtmodule}_MODULE_MINOR_VERSION})
            message(SEND_ERROR \"Qt6${qtmodule}_VERSION_MINOR variable was not ${CMAKE_${qtmodule}_MODULE_MINOR_VERSION}. Got \${Qt6${qtmodule}_VERSION_MINOR} instead.\")
          endif()
          if(NOT \"\${Qt6${qtmodule}_VERSION_PATCH}\" VERSION_EQUAL ${CMAKE_${qtmodule}_MODULE_PATCH_VERSION})
            message(SEND_ERROR \"Qt6${qtmodule}_VERSION_PATCH variable was not ${CMAKE_${qtmodule}_MODULE_PATCH_VERSION}. Got \${Qt6${qtmodule}_VERSION_PATCH} instead.\")
          endif()\n"
        )
    endif()
    set(libraries_string "${libraries_string} Qt6::${qtmodule}")
  endwhile()

  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/module_includes/CMakeLists.txt"
    "
      cmake_minimum_required(VERSION 3.14)
      project(module_includes)

      ${packages_string}

      add_executable(module_includes_exe \"\${CMAKE_CURRENT_SOURCE_DIR}/main.cpp\")
      target_link_libraries(module_includes_exe ${libraries_string})\n"
  )

  set(all_args ${ARGN})
  set(includes_string "")
  set(instances_string "")
  while(all_args)
    list(GET all_args 0 qtmodule)
    list(GET all_args 1 qtclass)
    if (${qtclass}_NAMESPACE)
      set(qtinstancetype ${${qtclass}_NAMESPACE}::${qtclass})
    else()
      set(qtinstancetype ${qtclass})
    endif()
    list(REMOVE_AT all_args 0 1)
    set(includes_string
      "${includes_string}
      #include <${qtclass}>
      #include <Qt${qtmodule}/${qtclass}>
      #include <Qt${qtmodule}>
      #include <Qt${qtmodule}/Qt${qtmodule}>"
    )
    set(instances_string
    "${instances_string}
    ${qtinstancetype} local${qtclass};
    ")
  endwhile()

  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/module_includes/main.cpp"
    "

    ${includes_string}

    int main(int, char **) { ${instances_string} return 0; }\n"
  )

  add_test(module_includes ${CMAKE_CTEST_COMMAND}
    --build-and-test
    "${CMAKE_CURRENT_BINARY_DIR}/module_includes/"
    "${CMAKE_CURRENT_BINARY_DIR}/module_includes/build"
    --build-config "${CMAKE_BUILD_TYPE}"
    --build-generator "${CMAKE_GENERATOR}"
    --build-makeprogram "${CMAKE_MAKE_PROGRAM}"
    --build-project module_includes
    --build-options "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}" ${BUILD_OPTIONS_LIST}
  )
endfunction()
