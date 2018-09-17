// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tss_adapter.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string.h>

#include "debug.h"
#include "log.h"

#include "tss2_mu.h"

namespace tpm_js {
namespace {

//
// Initialize a SAPI context using the TCTI context provided by the caller.
// This function allocates memory for the SAPI context and returns it to the
// caller. This memory must be freed by the caller.
//
TSS2_SYS_CONTEXT *sapi_init_from_tcti_ctx(TSS2_TCTI_CONTEXT *tcti_ctx) {
  TSS2_SYS_CONTEXT *sapi_ctx;
  TSS2_RC rc;
  size_t size;
  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

  size = Tss2_Sys_GetContextSize(0);
  sapi_ctx = (TSS2_SYS_CONTEXT *)calloc(1, size);
  if (sapi_ctx == NULL) {
    fprintf(stderr, "Failed to allocate 0x%zx bytes for the SAPI context\n",
            size);
    return NULL;
  }
  rc = Tss2_Sys_Initialize(sapi_ctx, size, tcti_ctx, &abi_version);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize SAPI context: 0x%x\n", rc);
    free(sapi_ctx);
    return NULL;
  }
  return sapi_ctx;
}

//
// Teardown and free the resources associated with a SAPI context structure.
//
void sapi_teardown(TSS2_SYS_CONTEXT *sapi_context) {
  Tss2_Sys_Finalize(sapi_context);
  free(sapi_context);
}

std::string HexDumpBuffer(const std::vector<uint8_t> &buffer) {
  std::stringstream outstream;
  uint8_t buff[17];
  size_t i = 0;

  outstream << std::hex;

  for (i = 0; i < buffer.size(); i++) {
    if ((i % 16) == 0) {
      // Skip zeroth line.
      if (i != 0) {
        outstream << "  " << buff << std::endl;
      }

      // Output offset.
      outstream << "  " << std::setw(4) << std::setfill('0')
                << static_cast<unsigned int>(i);
    }

    outstream << " " << std::setw(2) << std::setfill('0')
              << static_cast<unsigned int>(buffer[i]);

    // Store printable ASCII character for later.
    if ((buffer[i] < 0x20) || (buffer[i] > 0x7e)) {
      buff[i % 16] = '.';
    } else {
      buff[i % 16] = buffer[i];
    }
    buff[(i % 16) + 1] = '\0';
  }

  outstream << std::dec;

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    outstream << "   ";
    i++;
  }

  // And print the final ASCII bit.
  outstream << "  " << buff << std::endl;

  return outstream.str();
}

uint32_t UnmarshalCodeFromHeader(const std::vector<uint8_t> &buffer) {
  size_t offset = 0;
  TPM2_ST tag;
  uint32_t size;
  uint32_t code;
  TSS2_RC rc =
      Tss2_MU_TPM2_ST_Unmarshal(buffer.data(), buffer.size(), &offset, &tag);
  if (rc != TPM2_RC_SUCCESS) {
    return -1;
  }
  rc = Tss2_MU_UINT32_Unmarshal(buffer.data(), buffer.size(), &offset, &size);
  if (rc != TPM2_RC_SUCCESS) {
    return -1;
  }
  rc = Tss2_MU_UINT32_Unmarshal(buffer.data(), buffer.size(), &offset, &code);
  if (rc != TPM2_RC_SUCCESS) {
    return -1;
  }
  return code;
}

} // namespace

TssAdapter::TssAdapter(RunCommand runner)
    : runner_(runner), tcti_context_({}), sys_context_(nullptr) {
  // Init TCTI adapter
  tcti_context_.common.magic = 0;
  tcti_context_.common.version = 1;
  tcti_context_.common.transmit = &TssAdapter::SendCommandWrapper;
  tcti_context_.common.receive = &TssAdapter::ReceiveResponseWrapper;
  tcti_context_.common.finalize = nullptr;
  tcti_context_.common.cancel = nullptr;
  tcti_context_.common.getPollHandles = nullptr;
  tcti_context_.common.setLocality = nullptr;
  tcti_context_.opaque = this;
  sys_context_ = sapi_init_from_tcti_ctx(
      reinterpret_cast<TSS2_TCTI_CONTEXT *>(&tcti_context_.common));
  assert(sys_context_ != nullptr);
}

TssAdapter::~TssAdapter() { sapi_teardown(sys_context_); }

TSS2_SYS_CONTEXT *TssAdapter::GetSysContext() { return sys_context_; }

TSS2_RC TssAdapter::SendCommand(size_t command_size,
                                uint8_t const *command_buffer) {
  std::vector<uint8_t> data(command_buffer, command_buffer + command_size);
  pending_command_ = data;
  return TSS2_RC_SUCCESS;
}

TSS2_RC TssAdapter::SendCommandWrapper(TSS2_TCTI_CONTEXT *tcti_context,
                                       size_t command_size,
                                       uint8_t const *command_buffer) {
  TSS2_TCTI_CONTEXT_ADAPTER *context =
      reinterpret_cast<TSS2_TCTI_CONTEXT_ADAPTER *>(
          reinterpret_cast<char *>(tcti_context) -
          offsetof(TSS2_TCTI_CONTEXT_ADAPTER, common));
  TssAdapter *that = reinterpret_cast<TssAdapter *>(context->opaque);
  return that->SendCommand(command_size, command_buffer);
}

TSS2_RC TssAdapter::ReceiveResponse(size_t *response_size,
                                    unsigned char *response_buffer,
                                    int32_t unused_timeout) {
  LOG1("About to execute command %s\n",
       GetTpmCommandName(UnmarshalCodeFromHeader(pending_command_)).c_str());
  LOG2("Command buffer (%d):\n%s", pending_command_.size(),
       HexDumpBuffer(pending_command_).c_str());
  const std::vector<uint8_t> data = runner_(pending_command_);
  LOG2("Response buffer (%d):\n%s", data.size(), HexDumpBuffer(data).c_str());
  assert(data.size() <= *response_size);
  *response_size = data.size();
  memcpy(response_buffer, data.data(), data.size());
  pending_command_ = {};
  return TSS2_RC_SUCCESS;
}

TSS2_RC TssAdapter::ReceiveResponseWrapper(TSS2_TCTI_CONTEXT *tcti_context,
                                           size_t *response_size,
                                           unsigned char *response_buffer,
                                           int32_t timeout) {
  TSS2_TCTI_CONTEXT_ADAPTER *context =
      reinterpret_cast<TSS2_TCTI_CONTEXT_ADAPTER *>(
          reinterpret_cast<char *>(tcti_context) -
          offsetof(TSS2_TCTI_CONTEXT_ADAPTER, common));
  TssAdapter *that = reinterpret_cast<TssAdapter *>(context->opaque);
  return that->ReceiveResponse(response_size, response_buffer, timeout);
}

} // namespace tpm_js
