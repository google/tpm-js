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
if(NOT TPM2TSS_ROOT_DIR)
  set(TPM2TSS_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tpm2-tss/)
endif()

file(GLOB_RECURSE TSS2_SYS_FILES ${TPM2TSS_ROOT_DIR}/src/tss2-sys/*.c)
file(GLOB_RECURSE TSS2_MU_FILES ${TPM2TSS_ROOT_DIR}/src/tss2-mu/*.c)

#
# TPM2TSS library.
#

add_library(tpm2tss_lib STATIC
  ${TSS2_SYS_FILES}
  ${TSS2_MU_FILES}
  ${TPM2TSS_ROOT_DIR}/src/util/log.c
)

target_include_directories(tpm2tss_lib
  PRIVATE
  ${TPM2TSS_ROOT_DIR}/src
  ${TPM2TSS_ROOT_DIR}/src/tss2-sys
  PUBLIC
  ${TPM2TSS_ROOT_DIR}/include/tss2
  ${TPM2TSS_ROOT_DIR}/test/integration
)

target_compile_definitions(tpm2tss_lib PUBLIC -DMAXLOGLEVEL=6)
