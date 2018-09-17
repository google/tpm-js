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

if(NOT GOOGLEMOCK_ROOT_DIR)
  set(GOOGLEMOCK_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/googletest/googlemock)
endif()
if(EXISTS "${GOOGLEMOCK_ROOT_DIR}/CMakeLists.txt")
  add_subdirectory(${GOOGLEMOCK_ROOT_DIR})
  set(_GOOGLEMOCK_INCLUDE_DIR ${GOOGLEMOCK_ROOT_DIR}/include)
else()
  message(WARNING "Missing GOOGLEMOCK module")
endif()

if(NOT GOOGLETEST_ROOT_DIR)
  set(GOOGLETEST_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/googletest/googletest)
endif()
if(EXISTS "${GOOGLETEST_ROOT_DIR}/CMakeLists.txt")
  if(NOT TARGET gtest_main)
    add_subdirectory(${GOOGLETEST_ROOT_DIR})
  endif()
  set(_GOOGLETEST_INCLUDE_DIR ${GOOGLETEST_ROOT_DIR}/include)
else()
  message(WARNING "Missing GOOGLETEST module")
endif()
