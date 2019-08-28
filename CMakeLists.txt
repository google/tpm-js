# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
cmake_minimum_required(VERSION 3.3)
project("tpm-js")
enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

if(DEFINED ENV{EMSCRIPTEN})
  if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
  endif()
  if(CMAKE_BUILD_TYPE MATCHES Debug)
    # SAFE_HEAP=1 fails in TSS unmarshaling code due to alignments.
    set(EMSCRIPTEN_FLAGS
        "-O1"
        "-s ASSERTIONS=2"
        "-s SAFE_HEAP=0"
        "-s STACK_OVERFLOW_CHECK=2"
        "-s DISABLE_EXCEPTION_CATCHING=1"
        "-s ALLOW_MEMORY_GROWTH=1"
        "-s WASM=1"
       )
    string (REPLACE ";" " " EMSCRIPTEN_FLAGS "${EMSCRIPTEN_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EMSCRIPTEN_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EMSCRIPTEN_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EMSCRIPTEN_FLAGS}")
  elseif(CMAKE_BUILD_TYPE MATCHES Release)
    set(EMSCRIPTEN_FLAGS
        "-O2"
        "-s ASSERTIONS=1"
        "-s SAFE_HEAP=0"
        "-s STACK_OVERFLOW_CHECK=0"
        "-s DISABLE_EXCEPTION_CATCHING=1"
        "-s ALLOW_MEMORY_GROWTH=1"
        "-s WASM=1"
       )
    string (REPLACE ";" " " EMSCRIPTEN_FLAGS "${EMSCRIPTEN_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EMSCRIPTEN_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EMSCRIPTEN_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EMSCRIPTEN_FLAGS}")
  else()
    message(FATAL_ERROR "Unknown build type: ${CMAKE_BUILD_TYPE}")
  endif()
  # Use C++11 everywhere with Emscripten
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  # C++ demangle support with Emscripten
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s DEMANGLE_SUPPORT=1")
  set(BUILDING_WASM 1)
  add_definitions(-DBUILDING_WASM=1)
  # .html suffix tells emcc to build HTML+JS files separately. This improves load time.
  set(CMAKE_EXECUTABLE_SUFFIX ".html")
endif()

# Adds a test target.
# With emscripten, tests are executed with node-js.
function(add_test_target test_target)
  if(BUILDING_WASM)
    add_test(NAME ${test_target} COMMAND node ${test_target})
    set_target_properties(${test_target} PROPERTIES LINK_FLAGS "--bind")
  else()
    add_test(${test_target} ${test_target})
  endif()
  add_dependencies(check ${test_target})
endfunction()


#
# Third-party includes
#
include(third_party/googletest.cmake)
include(third_party/ssl.cmake)
include(third_party/ibmswtpm2.cmake)
include(third_party/tpm2tss.cmake)

#
# IBMSWTPM2 library
#
add_library(ibmswtpm2_lib STATIC
  ${IBMSWTPM2_SOURCES}
)

target_include_directories(ibmswtpm2_lib
  PUBLIC
  ${IBMSWTPM2_ROOT_DIR}
  PRIVATE
  ${_SSL_INCLUDE_DIR}
)

target_compile_definitions(ibmswtpm2_lib PUBLIC -DTPM_POSIX -DNO_BIT_FIELD_STRUCTURES)

#
# Simulator library.
#
add_library(simulator_lib STATIC
  src/simulator.cc
  src/tss_adapter.cc
  src/app.cc
  src/log.cc
  src/debug.cc
)

target_include_directories(simulator_lib
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  src/
  ${_SSL_INCLUDE_DIR}
)

target_link_libraries(simulator_lib
  ibmswtpm2_lib
  tpm2tss_lib
  ${_SSL_LIBRARIES}
)

#
# simulator_test
#
add_executable(simulator_test
  src/simulator_test.cc
)

target_include_directories(simulator_test
  PRIVATE
  ${_GOOGLETEST_INCLUDE_DIR}
)

target_link_libraries(simulator_test
  simulator_lib
  gmock
  gtest
  gtest_main
)

add_test_target(simulator_test)

#
# tss_adapter_test
#
add_executable(tss_adapter_test
  src/tss_adapter_test.cc
)

target_include_directories(tss_adapter_test
  PRIVATE
  ${_GOOGLETEST_INCLUDE_DIR}
  ${_GOOGLEMOCK_INCLUDE_DIR}
)

target_link_libraries(tss_adapter_test
  simulator_lib
  gmock
  gtest
  gtest_main
)

add_test_target(tss_adapter_test)

#
# app_test
#
add_executable(app_test
  src/app_test.cc
)

target_include_directories(app_test
  PRIVATE
  ${_GOOGLETEST_INCLUDE_DIR}
)

target_link_libraries(app_test
  simulator_lib
  gmock
  gtest
  gtest_main
)

add_test_target(app_test)


if(BUILDING_WASM)
  #
  # Emscripten bindings.
  #
  add_executable(bindings
    src/bindings.cc
  )

  set_target_properties(bindings PROPERTIES LINK_FLAGS "--bind")

  target_include_directories(bindings
    PRIVATE
    src/
  )

  target_link_libraries(bindings
    simulator_lib
  )

  #
  # Web package.
  #
  #  web/
  #  ├── HTML files rendered from html/templates.
  #  ├── css
  #  │   └── CSS files from html/css.
  #  ├── images
  #  │   └── Image files from html/images.
  #  ├── js
  #  │   └── JS files from html/js.
  #  └── wasm
  #      └── bindings.(js|wasm) that were built by bindings target above.
  #
  set(TEMPLATE_BUILDER ${CMAKE_CURRENT_SOURCE_DIR}/tools/template_builder.py)
  set(WEB_PACKAGE_DIR ${CMAKE_CURRENT_BINARY_DIR}/web)

  # Copy css files.
  add_custom_command(
    OUTPUT ${WEB_PACKAGE_DIR}/css
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/html/css ${WEB_PACKAGE_DIR}/css
    DEPENDS html/css/*
  )

  add_custom_target(web_css ALL
    DEPENDS
    ${WEB_PACKAGE_DIR}/css
  )

  # Copy image files.
  add_custom_command(
    OUTPUT ${WEB_PACKAGE_DIR}/images
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/html/images ${WEB_PACKAGE_DIR}/images
    DEPENDS html/images/*
  )

  add_custom_target(web_images ALL
    DEPENDS
    ${WEB_PACKAGE_DIR}/images
  )

  # Copy js files.
  add_custom_command(
    OUTPUT ${WEB_PACKAGE_DIR}/js
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/html/js ${WEB_PACKAGE_DIR}/js
    DEPENDS html/js/*
  )

  add_custom_target(web_js ALL
    DEPENDS
    ${WEB_PACKAGE_DIR}/js
  )

  # Copy wasm files.
  add_custom_command(
    OUTPUT ${WEB_PACKAGE_DIR}/wasm
    COMMAND ${CMAKE_COMMAND} -E make_directory ${WEB_PACKAGE_DIR}/wasm
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/bindings.js ${WEB_PACKAGE_DIR}/wasm/bindings.js
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/bindings.wasm ${WEB_PACKAGE_DIR}/wasm/bindings.wasm
    DEPENDS bindings
  )

  add_custom_target(web_wasm ALL
    DEPENDS
    ${WEB_PACKAGE_DIR}/wasm
  )

  # Render html templates.
  foreach(template index.html)
    set(output ${WEB_PACKAGE_DIR}/${template})
    add_custom_command(
      OUTPUT ${output}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${WEB_PACKAGE_DIR}
      COMMAND ${TEMPLATE_BUILDER} html/templates ${template} ${output}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      DEPENDS html/templates/*
    )
    add_custom_target(${template} ALL
      DEPENDS
      ${output}
      )
  endforeach(template)

endif() # BUILDING_WASM
