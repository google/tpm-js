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

#include "keyed_hash.h"

#include <cassert>

#include "log.h"

#include "tss2_mu.h"

#include "openssl/digest.h"
#include "openssl/rand.h"

namespace tpm_js {

KeyedHash::KeyedHash(const std::string &sensitive_data) {
  memset(&private_, 0, sizeof(private_));
  memset(&public_, 0, sizeof(public_));
  private_.sensitiveArea.sensitiveType = TPM2_ALG_KEYEDHASH;
  private_.sensitiveArea.seedValue.size = EVP_MD_size(EVP_sha256());
  RAND_bytes(private_.sensitiveArea.seedValue.buffer,
             private_.sensitiveArea.seedValue.size);
  private_.sensitiveArea.sensitive.bits.size = sensitive_data.size();
  assert(sensitive_data.size() <=
         sizeof(private_.sensitiveArea.sensitive.bits.buffer));
  memcpy(private_.sensitiveArea.sensitive.bits.buffer, sensitive_data.data(),
         sensitive_data.size());

  public_.type = TPM2_ALG_KEYEDHASH;
  public_.nameAlg = TPM2_ALG_SHA256;
  public_.objectAttributes = TPMA_OBJECT_USERWITHAUTH;
  public_.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

  // Bind private to public by hashing private_ into public_.unique.
  EVP_MD_CTX mdctx;
  EVP_DigestInit(&mdctx, EVP_sha256());
  EVP_DigestUpdate(&mdctx, private_.sensitiveArea.seedValue.buffer,
                   private_.sensitiveArea.seedValue.size);
  EVP_DigestUpdate(&mdctx, private_.sensitiveArea.sensitive.bits.buffer,
                   private_.sensitiveArea.sensitive.bits.size);
  EVP_DigestFinal(&mdctx, public_.unique.keyedHash.buffer, nullptr);
  public_.unique.keyedHash.size = EVP_MD_size(EVP_sha256());
}

KeyedHash::~KeyedHash() {}

std::vector<uint8_t> KeyedHash::GetEncodedPrivate() {
  std::vector<uint8_t> buffer(sizeof(TPM2B_SENSITIVE), 0);
  size_t offset = 0;
  TSS2_RC rc = Tss2_MU_TPM2B_SENSITIVE_Marshal(&private_, buffer.data(),
                                               buffer.size(), &offset);
  assert(rc == TPM2_RC_SUCCESS);
  buffer.resize(offset);
  return buffer;
}

std::vector<uint8_t> KeyedHash::GetEncodedPublic() {
  std::vector<uint8_t> buffer(sizeof(TPM2B_PUBLIC), 0);
  size_t offset = 0;
  TSS2_RC rc = Tss2_MU_TPMT_PUBLIC_Marshal(&public_, buffer.data(),
                                           buffer.size(), &offset);
  assert(rc == TPM2_RC_SUCCESS);
  buffer.resize(offset);
  return buffer;
}

std::vector<uint8_t> KeyedHash::GetEncodedPublicName() {
  TPMT_HA name = {};
  name.hashAlg = TPM2_ALG_SHA256;

  const auto public_area = GetEncodedPublic();
  EVP_MD_CTX mdctx;
  EVP_DigestInit(&mdctx, EVP_sha256());
  EVP_DigestUpdate(&mdctx, public_area.data(), public_area.size());
  EVP_DigestFinal(&mdctx, name.digest.sha256, nullptr);

  std::vector<uint8_t> buffer(sizeof(TPM2B_DIGEST), 0);
  size_t offset = 0;
  TSS2_RC rc =
      Tss2_MU_TPMT_HA_Marshal(&name, buffer.data(), buffer.size(), &offset);
  assert(rc == TPM2_RC_SUCCESS);
  buffer.resize(offset);
  return buffer;
}

} // namespace tpm_js
