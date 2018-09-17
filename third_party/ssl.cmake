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
if(NOT BORINGSSL_ROOT_DIR)
  set(BORINGSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl)
endif()
if(EXISTS "${BORINGSSL_ROOT_DIR}/CMakeLists.txt")
  # patch makefile.
  if(NOT EXISTS "${BORINGSSL_ROOT_DIR}/patched")
    message(STATUS "Patching BoringSSL CMakeLists.txt")
    execute_process(
      COMMAND sh -c "sed -i 's/-ggdb//' CMakeLists.txt && touch patched"
      WORKING_DIRECTORY ${BORINGSSL_ROOT_DIR}
    )
  endif()
  # make boringssl buildable with Visual Studio
  set(OPENSSL_NO_ASM ON)
  if(BUILDING_WASM)
    # crypto_test fails to build to WASM. Exclude ssl targets from all.
    add_subdirectory(${BORINGSSL_ROOT_DIR} third_party/boringssl EXCLUDE_FROM_ALL)
  else()
    add_subdirectory(${BORINGSSL_ROOT_DIR} third_party/boringssl)
  endif()
  if(TARGET ssl)
    set(_SSL_LIBRARIES ssl)
    set(_SSL_INCLUDE_DIR ${BORINGSSL_ROOT_DIR}/include)
  endif()
else()
  message(WARNING "Missing BoringSSL module")
endif()
