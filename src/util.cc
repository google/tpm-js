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

#include "util.h"

#include <cassert>
#include <endian.h>

#include "tss2_mu.h"

#include "openssl/digest.h"
#include "openssl/hmac.h"

namespace tpm_js {
namespace {

constexpr uint8_t kDelimiter = 0;

} // namespace

AttestInfo
Util::UnmarshalAttestBuffer(const std::vector<uint8_t> &tpm2b_attest) {
  TPMS_ATTEST attest = {};

  AttestInfo result;
  result.rc = Tss2_MU_TPMS_ATTEST_Unmarshal(
      tpm2b_attest.data(), tpm2b_attest.size(), nullptr, &attest);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.magic = attest.magic;
    result.type = attest.type;
    result.signer_qualified_name = std::vector<uint8_t>(
        attest.qualifiedSigner.name,
        attest.qualifiedSigner.name + attest.qualifiedSigner.size);
    result.nonce =
        std::vector<uint8_t>(attest.extraData.buffer,
                             attest.extraData.buffer + attest.extraData.size);
    if (attest.type == TPM2_ST_ATTEST_QUOTE) {
      result.selected_pcr_digest =
          std::vector<uint8_t>(attest.attested.quote.pcrDigest.buffer,
                               attest.attested.quote.pcrDigest.buffer +
                                   attest.attested.quote.pcrDigest.size);
    }
  }
  return result;
}

std::vector<uint8_t> Util::KDFa(int hash_algo, const std::vector<uint8_t> &key,
                                const std::string &label,
                                const std::vector<uint8_t> &context_u,
                                const std::vector<uint8_t> &context_v,
                                int bits) {
  int bytes = (bits + 7) / 8;
  std::vector<uint8_t> output(bytes, 0);

  uint32_t serialized_size_bits = be32toh(output.size() * 8);

  assert(hash_algo == TPM2_ALG_SHA256);
  const uint32_t blocks =
      (output.size() + TPM2_SHA256_DIGEST_SIZE - 1) / TPM2_SHA256_DIGEST_SIZE;

  auto output_it = output.begin();
  for (uint32_t block = 1; block <= blocks; ++block) {
    uint32_t serialized_block = be32toh(block);

    bssl::ScopedHMAC_CTX hmac;
    std::vector<uint8_t> block_digest(TPM2_SHA256_DIGEST_SIZE);
    uint32_t block_digest_len = block_digest.size();
    HMAC_Init_ex(hmac.get(), key.data(), key.size(), EVP_sha256(),
                 /*impl=*/nullptr);
    HMAC_Update(hmac.get(),
                reinterpret_cast<const uint8_t *>(&serialized_block),
                sizeof(serialized_block));
    HMAC_Update(hmac.get(), reinterpret_cast<const uint8_t *>(label.data()),
                label.size());
    HMAC_Update(hmac.get(), &kDelimiter, sizeof(kDelimiter));
    HMAC_Update(hmac.get(), context_u.data(), context_u.size());
    HMAC_Update(hmac.get(), context_v.data(), context_v.size());
    HMAC_Update(hmac.get(),
                reinterpret_cast<const uint8_t *>(&serialized_size_bits),
                sizeof(serialized_size_bits));
    HMAC_Final(hmac.get(), block_digest.data(), &block_digest_len);

    size_t to_write = std::min(block_digest.size(),
                               static_cast<size_t>(output.end() - output_it));
    output_it = std::copy_n(block_digest.begin(), to_write, output_it);
  }

  return output;
}

} // namespace tpm_js
