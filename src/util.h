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

#include <string>
#include <vector>

namespace tpm_js {

struct AttestInfo {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  uint32_t magic;
  int type;
  std::vector<uint8_t> signer_qualified_name;
  std::vector<uint8_t> nonce;
  // Valid only if type == TPM2_ST_ATTEST_QUOTE.
  std::vector<uint8_t> selected_pcr_digest;
};

// Utility functions.
class Util {
public:
  // Unmarshals TPM2B_ATTEST structure from its wire representation.
  static AttestInfo
  UnmarshalAttestBuffer(const std::vector<uint8_t> &tpm2b_attest);

  // KDFa implements TPM 2.0's default key derivation function.
  // The key & label parameters must not be zero length.
  // The label parameter is a non-null-terminated string.
  // The contextU & contextV parameters are optional.
  static std::vector<uint8_t>
  KDFa(int hash_algo, const std::vector<uint8_t> &key, const std::string &label,
       const std::vector<uint8_t> &context_u,
       const std::vector<uint8_t> &context_v, int bits);

private:
  // static only
  ~Util();
};

} // namespace tpm_js
