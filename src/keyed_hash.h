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

#include "tss_adapter.h"

namespace tpm_js {

// Represents a TPM2_ALG_KEYEDHASH object with private and public parts.
class KeyedHash {
public:
  // |sensitive_data| is a blob sealed to this object.
  KeyedHash(const std::string &sensitive_data);
  ~KeyedHash();

  // Serializes the private structure in TPM wire format.
  std::vector<uint8_t> GetEncodedPrivate();

  // Serializes the public structure in TPM wire format.
  std::vector<uint8_t> GetEncodedPublic();

  // Computes the Digest-based Name from the public area.
  // Returns the name is TPM wire format.
  std::vector<uint8_t> GetEncodedPublicName();

private:
  TPM2B_SENSITIVE private_;
  TPMT_PUBLIC public_;
};

} // namespace tpm_js
