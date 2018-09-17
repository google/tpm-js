/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <functional>
#include <vector>

#include "tss2_sys.h"
#include "tss2_tcti.h"

namespace tpm_js {

// Adapter between Intel TSS software stack and TPM-JS simulator.
class TssAdapter {
public:
  using RunCommand =
      std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)>;
  explicit TssAdapter(RunCommand runner);
  ~TssAdapter();

  TSS2_SYS_CONTEXT *GetSysContext();

private:
  TSS2_RC SendCommand(size_t command_size, uint8_t const *command_buffer);

  static TSS2_RC SendCommandWrapper(TSS2_TCTI_CONTEXT *tcti_context,
                                    size_t command_size,
                                    uint8_t const *command_buffer);

  TSS2_RC ReceiveResponse(size_t *response_size, unsigned char *response_buffer,
                          int32_t unused_timeout);

  static TSS2_RC ReceiveResponseWrapper(TSS2_TCTI_CONTEXT *tcti_context,
                                        size_t *response_size,
                                        unsigned char *response_buffer,
                                        int32_t timeout);

  // Extends TSS2_TCTI_CONTEXT_COMMON_V1 with an opaque pointer.
  // This pointer holds the IntelTssAdapter instance.
  typedef struct {
    TSS2_TCTI_CONTEXT_COMMON_V1 common;
    void *opaque;
  } TSS2_TCTI_CONTEXT_ADAPTER;

  RunCommand runner_;
  TSS2_TCTI_CONTEXT_ADAPTER tcti_context_;
  TSS2_SYS_CONTEXT *sys_context_;
  std::vector<uint8_t> pending_command_;
};

} // namespace tpm_js
