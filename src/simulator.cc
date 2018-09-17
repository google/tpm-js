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

#include "simulator.h"

#include <cassert>

#include "log.h"

extern "C" {
// clang-format off
#include "Tpm.h"
#include "TpmTcpProtocol.h"
#include "Simulator_fp.h"
// clang-format on
}

extern "C" BOOL s_isPowerOn;
extern "C" BOOL g_initialized;
extern "C" BOOL g_manufactured;
extern "C" uint8_t *GetPcrPointer(TPM_ALG_ID alg, UINT32 pcr);

namespace tpm_js {

void Simulator::PowerOn() {
  LOG1("PowerOn\n");
  _rpc__Signal_PowerOn(/*isReset=*/FALSE);
  _rpc__Signal_NvOn();
  _plat__Signal_PhysicalPresenceOn();
}

void Simulator::PowerOff() {
  LOG1("PowerOff\n");
  _rpc__Signal_PowerOff();
}

void Simulator::ManufactureReset() {
  LOG1("ManufactureReset\n");
  TPM_RC result = TPM_Manufacture(/*firstTime=*/TRUE);
  assert(result == TPM_RC_SUCCESS);
}

int Simulator::IsPoweredOn() { return s_isPowerOn; }
int Simulator::IsStarted() { return g_initialized; }
int Simulator::IsManufactured() { return g_manufactured; }

std::vector<uint8_t> Simulator::GetPcr(int n) {
  if (!g_manufactured) {
    return std::vector<uint8_t>{};
  }
  uint8_t *pcr = GetPcrPointer(TPM_ALG_SHA256, n);
  assert(pcr != nullptr);
  return std::vector<uint8_t>(pcr,
                              pcr + CryptHashGetDigestSize(TPM_ALG_SHA256));
}

std::vector<uint8_t> Simulator::GetEndorsementSeed() {
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t *>(gp.EPSeed.t.buffer),
      reinterpret_cast<const uint8_t *>(gp.EPSeed.t.buffer) + gp.EPSeed.t.size);
}

std::vector<uint8_t> Simulator::GetPlatformSeed() {
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t *>(gp.PPSeed.t.buffer),
      reinterpret_cast<const uint8_t *>(gp.PPSeed.t.buffer) + gp.PPSeed.t.size);
}

std::vector<uint8_t> Simulator::GetOwnerSeed() {
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t *>(gp.SPSeed.t.buffer),
      reinterpret_cast<const uint8_t *>(gp.SPSeed.t.buffer) + gp.SPSeed.t.size);
}

std::vector<uint8_t> Simulator::GetNullSeed() {
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t *>(gr.nullSeed.t.buffer),
      reinterpret_cast<const uint8_t *>(gr.nullSeed.t.buffer) +
          gr.nullSeed.t.size);
}

int Simulator::GetBootCounter() { return gp.totalResetCount; }

std::vector<uint8_t>
Simulator::ExecuteCommand(const std::vector<uint8_t> &command) {
  // Reserve space for response.
  std::vector<uint8_t> response(MAX_RESPONSE_SIZE);
  uint32_t response_size = MAX_RESPONSE_SIZE;
  uint8_t *request_ptr = const_cast<uint8_t *>(command.data());
  uint8_t *response_ptr = response.data();
  _plat__RunCommand(command.size(), request_ptr, &response_size, &response_ptr);
  // Resize to match actual response size.
  response.resize(response_size);
  return response;
}

} // namespace tpm_js
