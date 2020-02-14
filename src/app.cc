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

#include "app.h"

#include <cassert>
#include <endian.h>
#include <string.h>

#include "log.h"
#include "simulator.h"

#include "tss2_mu.h"

#include "openssl/digest.h"

namespace tpm_js {
namespace {

// IWG (TCG Infrastructure Work Group) default EK primary key policy.
// Copied from "TCG EK Credential Profile" specification, section 2.1.5,
// "Default EK Public Area Template"
const unsigned char kIwgPolicy[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
    0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
    0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA};

// Initializes a TPM2B structure to its max size:
// The size of the TPM2B structure minus the size of the '.size' field
template <typename T> constexpr size_t TPM2BStructSize() {
  return sizeof(T) - sizeof(T::size);
}

// Marshals TPM2B structs.
template <typename T,
          TSS2_RC (*Marshaler)(T const *, uint8_t *, size_t, size_t *)>
std::vector<uint8_t> TPM2BMarshal(T const *src) {
  std::vector<uint8_t> buffer(sizeof(*src), 0);
  TSS2_RC rc = Marshaler(src, buffer.data(), buffer.size(), nullptr);
  assert(rc == TPM2_RC_SUCCESS);
  return buffer;
}

// Unmarshals TPM2B structs.
template <typename T,
          TSS2_RC (*Unmarshaler)(uint8_t const *, size_t, size_t *, T *)>
T TPM2BUnmarshal(const std::vector<uint8_t> &buffer) {
  T result = {};
  TSS2_RC rc = Unmarshaler(buffer.data(), buffer.size(), nullptr, &result);
  assert(rc == TPM2_RC_SUCCESS);
  return result;
}

std::string CapUintToString(UINT32 value) {
  char result[5] = "    ";
  char *result_ptr = &result[0];
  *((UINT32 *)result_ptr) = be32toh(value);
  return std::string(&result[0], &result[4]);
}

TPM2B_PUBLIC GetDefaultEKTemplate() {
  TPM2B_PUBLIC in_public = {};
  in_public.publicArea.type = TPM2_ALG_RSA;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

  in_public.publicArea.authPolicy.size =
      sizeof(kIwgPolicy) / sizeof(kIwgPolicy[0]);
  memcpy(&in_public.publicArea.authPolicy.buffer, kIwgPolicy,
         in_public.publicArea.authPolicy.size);

  in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
  in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
  in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;

  in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;

  in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
  in_public.publicArea.parameters.rsaDetail.exponent = 0;
  in_public.publicArea.unique.rsa.size = 256;
  return in_public;
}

TPM2B_PUBLIC GetPublicRSA(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
  TPM2B_PUBLIC in_public = {};
  in_public.publicArea.type = TPM2_ALG_RSA;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  if (restricted) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  }
  if (auth_policy.size() == 0) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
  }
  if (decrypt) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
  }
  if (sign) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
  }
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

  in_public.publicArea.authPolicy.size = auth_policy.size();
  assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
  memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
         auth_policy.size());

  if (sign) {
    in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
        TPM2_ALG_NULL;
  } else {
    in_public.publicArea.parameters.rsaDetail.symmetric.algorithm =
        TPM2_ALG_AES;
  }
  in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
  in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
  if (sign && !decrypt) {
    in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
    in_public.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
        TPM2_ALG_SHA256;
  } else {
    in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
  }
  in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
  in_public.publicArea.parameters.rsaDetail.exponent = 0;
  in_public.publicArea.unique.rsa.size = 0;
  if (unique) {
    assert(unique->size < sizeof(in_public.publicArea.unique.rsa.buffer));
    in_public.publicArea.unique.rsa.size = unique->size;
    memcpy(in_public.publicArea.unique.rsa.buffer, unique->buffer,
           unique->size);
  }
  return in_public;
}

TPM2B_PUBLIC GetPublicECC(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
  TPM2B_PUBLIC in_public = {};
  in_public.publicArea.type = TPM2_ALG_ECC;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  if (restricted) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  }
  if (auth_policy.size() == 0) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
  }
  if (decrypt) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
  }
  if (sign) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
  }
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

  in_public.publicArea.authPolicy.size = auth_policy.size();
  assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
  memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
         auth_policy.size());

  if (sign) {
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm =
        TPM2_ALG_NULL;
  } else {
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm =
        TPM2_ALG_AES;
  }
  in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
  in_public.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
  if (sign) {
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        TPM2_ALG_SHA256;
  } else {
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
  }
  in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
  in_public.publicArea.unique.ecc.x.size = 0;
  in_public.publicArea.unique.ecc.y.size = 0;
  if (unique) {
    assert(unique->size < sizeof(in_public.publicArea.unique.ecc.x.buffer));
    in_public.publicArea.unique.ecc.x.size = unique->size;
    memcpy(in_public.publicArea.unique.ecc.x.buffer, unique->buffer,
           unique->size);
  }
  return in_public;
}

TPM2B_PUBLIC GetPublicSYM(int restricted, int decrypt, int sign,
                          const std::vector<uint8_t> &auth_policy,
                          const TPM2B_DIGEST *unique) {
  TPM2B_PUBLIC in_public = {};
  in_public.publicArea.type = TPM2_ALG_SYMCIPHER;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  if (restricted) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  }
  if (auth_policy.size() == 0) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
  }
  if (decrypt) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
  }
  if (sign) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
  }
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;

  in_public.publicArea.authPolicy.size = auth_policy.size();
  assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
  memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
         auth_policy.size());

  in_public.publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
  in_public.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
  in_public.publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;

  in_public.publicArea.unique.sym.size = 0;
  if (unique) {
    assert(unique->size < sizeof(in_public.publicArea.unique.sym.buffer));
    in_public.publicArea.unique.sym.size = unique->size;
    memcpy(in_public.publicArea.unique.sym.buffer, unique->buffer,
           unique->size);
  }
  return in_public;
}

TPM2B_PUBLIC GetPublicHASH(int restricted, int decrypt, int sign,
                           const std::vector<uint8_t> &auth_policy,
                           const TPM2B_DIGEST *unique,
                           const std::string &sensitive_data) {
  // When sealing sensitive data always clear restricted, decrypt and sign.
  // Additionally, clear data-origin since the TPM cannot be the data source.
  if (sensitive_data.size()) {
    restricted = decrypt = sign = 0;
  }
  TPM2B_PUBLIC in_public = {};
  in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  if (restricted) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  }
  if (auth_policy.size() == 0) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
  }
  if (decrypt) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
  }
  if (sign) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
  }
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  if (sensitive_data.size() == 0) {
    in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
  }

  in_public.publicArea.authPolicy.size = auth_policy.size();
  assert(auth_policy.size() <= sizeof(in_public.publicArea.authPolicy.buffer));
  memcpy(in_public.publicArea.authPolicy.buffer, auth_policy.data(),
         auth_policy.size());

  if (sign) {
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
        TPM2_ALG_XOR;
    in_public.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr
        .hashAlg = TPM2_ALG_SHA256;
    in_public.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr
        .kdf = TPM2_ALG_KDF1_SP800_108;
  } else {
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
        TPM2_ALG_NULL;
  }

  in_public.publicArea.unique.keyedHash.size = 0;
  if (unique) {
    assert(unique->size < sizeof(in_public.publicArea.unique.keyedHash.buffer));
    in_public.publicArea.unique.keyedHash.size = unique->size;
    memcpy(in_public.publicArea.unique.keyedHash.buffer, unique->buffer,
           unique->size);
  }
  return in_public;
}

// Builds NV space attributes for EK certificate.
TPMA_NV BuildNvSpaceAttributes() {
  TPMA_NV attributes = 0;
  // EK Credential attributes specified in the "TCG PC Client Platform, TPM
  // Profile (PTP) Specification" document.
  // REQUIRED: Writeable under platform auth.
  attributes |= TPMA_NV_PPWRITE;
  // OPTIONAL: Write-once; space must be deleted to be re-written.
  attributes |= TPMA_NV_WRITEDEFINE;
  // REQUIRED: Space created with platform auth.
  attributes |= TPMA_NV_PLATFORMCREATE;
  // REQUIRED: Readable under empty password?
  attributes |= TPMA_NV_AUTHREAD;
  // REQUIRED: Disable dictionary attack protection.
  attributes |= TPMA_NV_NO_DA;
  // OPTIONAL: Ownder readable.
  attributes |= TPMA_NV_OWNERREAD;
  // OPTIONAL: Readable under platform auth.
  attributes |= TPMA_NV_PPREAD;
  return attributes;
}

TPM2B_SENSITIVE_CREATE BuildInSensitive(const std::string &user_auth,
                                        const std::string &sensitive_data) {
  TPM2B_SENSITIVE_CREATE in_sensitive = {};
  assert(user_auth.size() <= sizeof(in_sensitive.sensitive.userAuth.buffer));
  in_sensitive.sensitive.userAuth.size = user_auth.size();
  memcpy(in_sensitive.sensitive.userAuth.buffer, user_auth.c_str(),
         user_auth.size());

  assert(sensitive_data.size() <= sizeof(in_sensitive.sensitive.data.buffer));
  in_sensitive.sensitive.data.size = sensitive_data.size();
  memcpy(in_sensitive.sensitive.data.buffer, sensitive_data.c_str(),
         sensitive_data.size());
  return in_sensitive;
}

TPM2B_DIGEST HashString(const std::string &str, const EVP_MD *evpmd) {
  EVP_MD_CTX mdctx;
  TPM2B_DIGEST digest = {};
  unsigned int len = sizeof(digest.buffer);
  EVP_DigestInit(&mdctx, evpmd);
  EVP_DigestUpdate(&mdctx, str.data(), str.size());
  EVP_DigestFinal(&mdctx, digest.buffer, &len);
  digest.size = len;
  return digest;
}

} // namespace

App *App::Get() {
  static App *instance = new App();
  return instance;
}

App::App()
    : tss_(&Simulator::ExecuteCommand), sessions_data_({}),
      sessions_data_out_({}) {
  ClearSessionData();
}

App::~App() {}

void App::ClearSessionData() {
  sessions_data_.auths[0].sessionHandle = TPM2_RS_PW;
  sessions_data_.auths[0].nonce.size = 0;
  sessions_data_.auths[0].hmac.size = 0;
  sessions_data_.auths[0].sessionAttributes = 0;

  sessions_data_.auths[1].sessionHandle = TPM2_RS_PW;
  sessions_data_.auths[1].nonce.size = 0;
  sessions_data_.auths[1].hmac.size = 0;
  sessions_data_.auths[1].sessionAttributes = 0;

  sessions_data_.count = 1;
  sessions_data_out_.count = 1;
}

int App::Startup() {
  LOG1("Startup\n");
  return Tss2_Sys_Startup(tss_.GetSysContext(), TPM2_SU_CLEAR);
}

int App::Shutdown() {
  LOG1("Shutdown\n");
  return Tss2_Sys_Shutdown(tss_.GetSysContext(),
                           /*cmdAuthsArray=*/nullptr, TPM2_SU_CLEAR,
                           /*rspAuthsArray=*/nullptr);
}

int App::Clear() {
  return Tss2_Sys_Clear(tss_.GetSysContext(), TPM2_RH_PLATFORM,
                        /*cmdAuthsArray=*/&sessions_data_,
                        /*rspAuthsArray=*/nullptr);
}

int App::ExtendPcr(int pcr, const std::string &str) {
  LOG1("ExtendPcr '%s'\n", str.c_str());
  TPM2B_DIGEST message = HashString(str, EVP_sha256());

  TPML_DIGEST_VALUES digests = {};
  digests.count = 1;
  digests.digests[0].hashAlg = TPM2_ALG_SHA256;
  memcpy(digests.digests[0].digest.sha256, message.buffer, message.size);
  TPM2_RC rc = Tss2_Sys_PCR_Extend(tss_.GetSysContext(), pcr, &sessions_data_,
                                   &digests, /*rspAuthsArray=*/nullptr);
  return rc;
}

std::vector<uint8_t> App::GetRandom(int num_bytes) {
  LOG1("GetRandom\n");
  TPM2B_DIGEST random_bytes = {
      TPM2BStructSize<TPM2B_DIGEST>(),
  };
  TPM2_RC rc =
      Tss2_Sys_GetRandom(tss_.GetSysContext(), /*cmdAuthsArray=*/nullptr,
                         num_bytes, &random_bytes, /*rspAuthsArray=*/nullptr);
  assert(rc == TPM2_RC_SUCCESS);
  return std::vector<uint8_t>(random_bytes.buffer,
                              random_bytes.buffer + random_bytes.size);
}

int App::SelfTest() {
  LOG1("SelfTest\n");
  TPM2_RC rc =
      Tss2_Sys_SelfTest(tss_.GetSysContext(), /*cmdAuthsArray=*/nullptr,
                        /*fullTest=*/TPM2_YES, /*rspAuthsArray=*/nullptr);
  return rc;
}

TpmProperties App::GetTpmProperties() {
  LOG1("GetTpmProperties\n");
  TpmProperties result = {};

  // Get spec version.
  TPMS_CAPABILITY_DATA capability_data =
      GetCapability(TPM2_CAP_TPM_PROPERTIES, TPM2_PT_REVISION);
  assert(capability_data.data.tpmProperties.count == 1);
  result.spec_version = capability_data.data.tpmProperties.tpmProperty[0].value;

  // Get manufacturer ID.
  capability_data =
      GetCapability(TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER);
  assert(capability_data.data.tpmProperties.count == 1);
  result.manufacturer_id =
      CapUintToString(capability_data.data.tpmProperties.tpmProperty[0].value);
  return result;
}

TPMS_CAPABILITY_DATA App::GetCapability(TPM2_CAP capability, UINT32 property) {
  TPMS_CAPABILITY_DATA capability_data = {};
  TPMI_YES_NO more;
  TPM2_RC rc = Tss2_Sys_GetCapability(
      tss_.GetSysContext(), /*cmdAuthsArray=*/nullptr, capability, property,
      /*propertyCount=*/1, &more, &capability_data, /*rspAuthsArray=*/nullptr);
  assert(rc == TPM2_RC_SUCCESS);
  return capability_data;
}

int App::TestHashParam(int hash_algo) {
  LOG1("TestHashParam %d\n", hash_algo);
  TPMT_PUBLIC_PARMS params = {};
  params.type = TPM2_ALG_KEYEDHASH;
  params.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
  params.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hash_algo;
  return Tss2_Sys_TestParms(tss_.GetSysContext(),
                            /*cmdAuthsArray=*/nullptr, &params,
                            /*rspAuthsArray=*/nullptr);
}

CreatePrimaryResult
App::CreatePrimaryFromTemplate(int hierarchy,
                               const TPM2B_SENSITIVE_CREATE &in_sensitive,
                               const TPM2B_PUBLIC &in_public) {
  TPM2B_PUBLIC out_public = {};

  TPM2B_DATA outside_info;
  outside_info.size = 0;

  TPML_PCR_SELECTION creation_pcr;
  creation_pcr.count = 0;

  TPM2B_CREATION_DATA creation_data = {
      .size = TPM2BStructSize<TPM2B_CREATION_DATA>(),
  };
  creation_data.size = 0;

  TPM2B_DIGEST creation_hash = {
      .size = TPM2BStructSize<TPM2B_DIGEST>(),
  };
  TPMT_TK_CREATION creation_ticket = {
      0, 0,
      .digest = {
          .size = TPM2BStructSize<TPM2B_DIGEST>(),
      }};

  TPM2B_NAME name = {
      .size = TPM2BStructSize<TPM2B_NAME>(),
  };
  CreatePrimaryResult result = {};
  result.rc = Tss2_Sys_CreatePrimary(
      tss_.GetSysContext(), hierarchy, &sessions_data_, &in_sensitive,
      &in_public, &outside_info, &creation_pcr, &result.handle, &out_public,
      &creation_data, &creation_hash, &creation_ticket, &name,
      &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    if (in_public.publicArea.type == TPM2_ALG_RSA) {
      result.rsa_public_n =
          std::vector<uint8_t>(out_public.publicArea.unique.rsa.buffer,
                               out_public.publicArea.unique.rsa.buffer +
                                   out_public.publicArea.unique.rsa.size);
    } else if (in_public.publicArea.type == TPM2_ALG_ECC) {
      result.ecc_public_x =
          std::vector<uint8_t>(out_public.publicArea.unique.ecc.x.buffer,
                               out_public.publicArea.unique.ecc.x.buffer +
                                   out_public.publicArea.unique.ecc.x.size);
      result.ecc_public_y =
          std::vector<uint8_t>(out_public.publicArea.unique.ecc.y.buffer,
                               out_public.publicArea.unique.ecc.y.buffer +
                                   out_public.publicArea.unique.ecc.y.size);
      result.ecc_curve_id = out_public.publicArea.parameters.eccDetail.curveID;
    }
    result.name = std::vector<uint8_t>(name.name, name.name + name.size);
    result.parent_name =
        std::vector<uint8_t>(creation_data.creationData.parentName.name,
                             creation_data.creationData.parentName.name +
                                 creation_data.creationData.parentName.size);

    result.parent_qualified_name = std::vector<uint8_t>(
        creation_data.creationData.parentQualifiedName.name,
        creation_data.creationData.parentQualifiedName.name +
            creation_data.creationData.parentQualifiedName.size);
  }

  return result;
}

CreatePrimaryResult
App::CreatePrimary(int hierarchy, int type, int restricted, int decrypt,
                   int sign, const std::string &unique,
                   const std::string &user_auth,
                   const std::string &sensitive_data,
                   const std::vector<uint8_t> &auth_policy) {
  LOG1("CreatePrimary %x %d '%s'\n", hierarchy, type, unique.c_str());
  assert((hierarchy == TPM2_RH_NULL) || (hierarchy == TPM2_RH_ENDORSEMENT) ||
         (hierarchy == TPM2_RH_PLATFORM) || (hierarchy == TPM2_RH_OWNER));
  assert((type == TPM2_ALG_RSA) || (type == TPM2_ALG_ECC) ||
         (type == TPM2_ALG_SYMCIPHER) || (type == TPM2_ALG_KEYEDHASH));

  TPM2B_DIGEST unique_digest = HashString(unique, EVP_sha256());
  TPM2B_PUBLIC in_public = {};
  if (type == TPM2_ALG_RSA) {
    in_public =
        GetPublicRSA(restricted, decrypt, sign, auth_policy, &unique_digest);
  } else if (type == TPM2_ALG_ECC) {
    in_public =
        GetPublicECC(restricted, decrypt, sign, auth_policy, &unique_digest);
  } else if (type == TPM2_ALG_SYMCIPHER) {
    in_public =
        GetPublicSYM(restricted, decrypt, sign, auth_policy, &unique_digest);
  } else /* type == TPM2_ALG_KEYEDHASH*/ {
    in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy,
                              &unique_digest, sensitive_data);
  }
  TPM2B_SENSITIVE_CREATE in_sensitive =
      BuildInSensitive(user_auth, sensitive_data);

  return CreatePrimaryFromTemplate(hierarchy, in_sensitive, in_public);
}

CreatePrimaryResult App::CreatePrimaryEndorsementKey() {
  TPM2B_SENSITIVE_CREATE in_sensitive = {};
  return CreatePrimaryFromTemplate(TPM2_RH_ENDORSEMENT, in_sensitive,
                                   GetDefaultEKTemplate());
}

CreateResult App::Create(uint32_t parent_handle, int type, int restricted,
                         int decrypt, int sign, const std::string &user_auth,
                         const std::string &sensitive_data,
                         const std::vector<uint8_t> &auth_policy) {
  LOG1("Create %x %d\n", parent_handle, type);
  assert((type == TPM2_ALG_RSA) || (type == TPM2_ALG_ECC) ||
         (type == TPM2_ALG_SYMCIPHER) || (type == TPM2_ALG_KEYEDHASH));

  TPM2B_PUBLIC in_public = {};
  if (type == TPM2_ALG_RSA) {
    in_public = GetPublicRSA(restricted, decrypt, sign, auth_policy, nullptr);
  } else if (type == TPM2_ALG_ECC) {
    in_public = GetPublicECC(restricted, decrypt, sign, auth_policy, nullptr);
  } else if (type == TPM2_ALG_SYMCIPHER) {
    in_public = GetPublicSYM(restricted, decrypt, sign, auth_policy, nullptr);
  } else /* type == TPM2_ALG_KEYEDHASH*/ {
    in_public = GetPublicHASH(restricted, decrypt, sign, auth_policy, nullptr,
                              sensitive_data);
  }

  TPM2B_PUBLIC out_public = {};

  TPM2B_SENSITIVE_CREATE in_sensitive =
      BuildInSensitive(user_auth, sensitive_data);

  TPM2B_DATA outside_info;
  outside_info.size = 0;

  TPML_PCR_SELECTION creation_pcr;
  creation_pcr.count = 0;

  TPM2B_PRIVATE out_private = {
      .size = TPM2BStructSize<TPM2B_PRIVATE>(),
  };

  TPM2B_CREATION_DATA creation_data = {
      .size = TPM2BStructSize<TPM2B_CREATION_DATA>(),
  };
  creation_data.size = 0;

  TPM2B_DIGEST creation_hash = {
      .size = TPM2BStructSize<TPM2B_DIGEST>(),
  };
  TPMT_TK_CREATION creation_ticket = {
      0, 0,
      .digest = {
          .size = TPM2BStructSize<TPM2B_DIGEST>(),
      }};

  CreateResult result = {};
  result.rc = Tss2_Sys_Create(
      tss_.GetSysContext(), parent_handle, &sessions_data_, &in_sensitive,
      &in_public, &outside_info, &creation_pcr, &out_private, &out_public,
      &creation_data, &creation_hash, &creation_ticket, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    if (type == TPM2_ALG_RSA) {
      result.rsa_public_n =
          std::vector<uint8_t>(out_public.publicArea.unique.rsa.buffer,
                               out_public.publicArea.unique.rsa.buffer +
                                   out_public.publicArea.unique.rsa.size);
    } else if (type == TPM2_ALG_ECC) {
      result.ecc_public_x =
          std::vector<uint8_t>(out_public.publicArea.unique.ecc.x.buffer,
                               out_public.publicArea.unique.ecc.x.buffer +
                                   out_public.publicArea.unique.ecc.x.size);
      result.ecc_public_y =
          std::vector<uint8_t>(out_public.publicArea.unique.ecc.y.buffer,
                               out_public.publicArea.unique.ecc.y.buffer +
                                   out_public.publicArea.unique.ecc.y.size);
      result.ecc_curve_id = out_public.publicArea.parameters.eccDetail.curveID;
    }
    result.tpm2b_private =
        TPM2BMarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Marshal>(
            &out_private);
    result.tpm2b_public =
        TPM2BMarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Marshal>(&out_public);
    result.parent_name =
        std::vector<uint8_t>(creation_data.creationData.parentName.name,
                             creation_data.creationData.parentName.name +
                                 creation_data.creationData.parentName.size);

    result.parent_qualified_name = std::vector<uint8_t>(
        creation_data.creationData.parentQualifiedName.name,
        creation_data.creationData.parentQualifiedName.name +
            creation_data.creationData.parentQualifiedName.size);
  }

  return result;
}

LoadResult App::Load(uint32_t parent_handle,
                     const std::vector<uint8_t> &tpm2b_private,
                     const std::vector<uint8_t> &tpm2b_public) {
  LOG1("Load %x\n", parent_handle);
  TPM2B_PRIVATE in_private =
      TPM2BUnmarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Unmarshal>(
          tpm2b_private);
  TPM2B_PUBLIC in_public =
      TPM2BUnmarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Unmarshal>(
          tpm2b_public);
  TPM2B_NAME name = {
      .size = TPM2BStructSize<TPM2B_NAME>(),
  };

  LoadResult result = {};
  result.rc = Tss2_Sys_Load(tss_.GetSysContext(), parent_handle,
                            &sessions_data_, &in_private, &in_public,
                            &result.handle, &name, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.name = std::vector<uint8_t>(name.name, name.name + name.size);
  }
  return result;
}

int App::FlushContext(uint32_t handle) {
  LOG1("FlushContext %x\n", handle);
  return Tss2_Sys_FlushContext(tss_.GetSysContext(), handle);
}

SignResult App::Sign(uint32_t key_handle, int type, const std::string &str) {
  LOG1("Sign %x '%s'\n", key_handle, str.c_str());
  assert((type == TPM2_ALG_RSA) || (type == TPM2_ALG_ECC));

  TPM2B_DIGEST message = HashString(str, EVP_sha256());

  // Use the object's default scheme.
  TPMT_SIG_SCHEME scheme = {};
  if (type == TPM2_ALG_RSA) {
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
  } else { /* type == TPM2_ALG_ECC */
    scheme.scheme = TPM2_ALG_ECDSA;
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
  }

  TPMT_TK_HASHCHECK validation = {};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;
  validation.digest.size = 0;

  TPMT_SIGNATURE signature = {};
  SignResult result;
  result.rc =
      Tss2_Sys_Sign(tss_.GetSysContext(), key_handle, &sessions_data_, &message,
                    &scheme, &validation, &signature, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.sign_algo = signature.sigAlg;
    if (type == TPM2_ALG_RSA) {
      result.hash_algo = signature.signature.rsassa.hash;
      result.rsa_ssa_sig =
          std::vector<uint8_t>(signature.signature.rsassa.sig.buffer,
                               signature.signature.rsassa.sig.buffer +
                                   signature.signature.rsassa.sig.size);
    } else { /* type == TPM2_ALG_ECC */
      result.hash_algo = signature.signature.ecdsa.hash;
      result.ecdsa_r =
          std::vector<uint8_t>(signature.signature.ecdsa.signatureR.buffer,
                               signature.signature.ecdsa.signatureR.buffer +
                                   signature.signature.ecdsa.signatureR.size);
      result.ecdsa_s =
          std::vector<uint8_t>(signature.signature.ecdsa.signatureS.buffer,
                               signature.signature.ecdsa.signatureS.buffer +
                                   signature.signature.ecdsa.signatureS.size);
    }
  }
  return result;
}

int App::VerifySignature(uint32_t key_handle, const std::string &str,
                         const SignResult &in_signature) {
  LOG1("VerifySignature %x '%s'\n", key_handle, str.c_str());
  TPM2B_DIGEST message = HashString(str, EVP_sha256());
  TPMT_SIGNATURE signature = {};
  signature.sigAlg = in_signature.sign_algo;
  if (signature.sigAlg == TPM2_ALG_RSASSA) {
    signature.signature.rsassa.hash = in_signature.hash_algo;
    memcpy(signature.signature.rsassa.sig.buffer,
           in_signature.rsa_ssa_sig.data(), in_signature.rsa_ssa_sig.size());
    signature.signature.rsassa.sig.size = in_signature.rsa_ssa_sig.size();
  } else if (signature.sigAlg == TPM2_ALG_ECDSA) {
    signature.signature.ecdsa.hash = in_signature.hash_algo;

    memcpy(signature.signature.ecdsa.signatureR.buffer,
           in_signature.ecdsa_r.data(), in_signature.ecdsa_r.size());
    signature.signature.ecdsa.signatureR.size = in_signature.ecdsa_r.size();

    memcpy(signature.signature.ecdsa.signatureS.buffer,
           in_signature.ecdsa_s.data(), in_signature.ecdsa_s.size());
    signature.signature.ecdsa.signatureS.size = in_signature.ecdsa_s.size();
  }

  TPMT_TK_VERIFIED validation = {};
  return Tss2_Sys_VerifySignature(tss_.GetSysContext(), key_handle,
                                  /*cmdAuthsArray=*/nullptr, &message,
                                  &signature, &validation, &sessions_data_out_);
}

std::vector<uint8_t> App::Encrypt(uint32_t key_handle,
                                  const std::vector<uint8_t> &message) {
  return EncryptDecrypt(key_handle, message, /*decrypt=*/false);
}

std::vector<uint8_t> App::Decrypt(uint32_t key_handle,
                                  const std::vector<uint8_t> &message) {
  return EncryptDecrypt(key_handle, message, /*decrypt=*/true);
}

std::vector<uint8_t> App::EncryptDecrypt(uint32_t key_handle,
                                         const std::vector<uint8_t> &message,
                                         bool decrypt) {
  TPM2B_IV iv_in = {
      .size = TPM2BStructSize<TPM2B_IV>(),
  };

  TPM2B_IV iv_out = {
      .size = TPM2BStructSize<TPM2B_IV>(),
  };

  TPM2B_MAX_BUFFER data_in = {};
  data_in.size = message.size();
  assert(message.size() <= sizeof(data_in.buffer));
  memcpy(data_in.buffer, message.data(), message.size());

  TPM2B_MAX_BUFFER data_out = {
      .size = TPM2BStructSize<TPM2B_MAX_BUFFER>(),
  };

  TPM2_RC rc =
      Tss2_Sys_EncryptDecrypt(tss_.GetSysContext(), key_handle, &sessions_data_,
                              (decrypt ? TPM2_YES : TPM2_NO),
                              /*mode=*/TPM2_ALG_NULL, &iv_in, &data_in,
                              &data_out, &iv_out, &sessions_data_out_);
  assert(rc == TPM2_RC_SUCCESS);

  return std::vector<uint8_t>(data_out.buffer, data_out.buffer + data_out.size);
}

std::vector<uint8_t> App::RSAEncrypt(uint32_t key_handle,
                                     const std::vector<uint8_t> &message) {
  TPM2B_PUBLIC_KEY_RSA data_in = {};
  data_in.size = message.size();
  assert(message.size() <= sizeof(data_in.buffer));
  memcpy(data_in.buffer, message.data(), message.size());

  TPMT_RSA_DECRYPT scheme = {
      .scheme = TPM2_ALG_RSAES,
  };

  TPM2B_DATA outside_info;
  outside_info.size = 0;

  TPM2B_PUBLIC_KEY_RSA data_out = {
      .size = TPM2BStructSize<TPM2B_PUBLIC_KEY_RSA>(),
  };

  TPM2_RC rc =
      Tss2_Sys_RSA_Encrypt(tss_.GetSysContext(), key_handle,
                           /*cmdAuthsArray=*/nullptr, &data_in, &scheme,
                           &outside_info, &data_out, /*rspAuthsArray=*/nullptr);
  assert(rc == TPM2_RC_SUCCESS);

  return std::vector<uint8_t>(data_out.buffer, data_out.buffer + data_out.size);
}

std::vector<uint8_t> App::RSADecrypt(uint32_t key_handle,
                                     const std::vector<uint8_t> &message) {
  TPM2B_PUBLIC_KEY_RSA data_in = {};
  data_in.size = message.size();
  assert(message.size() <= sizeof(data_in.buffer));
  memcpy(data_in.buffer, message.data(), message.size());

  TPMT_RSA_DECRYPT scheme = {
      .scheme = TPM2_ALG_RSAES,
  };

  TPM2B_DATA outside_info;
  outside_info.size = 0;

  TPM2B_PUBLIC_KEY_RSA data_out = {
      .size = TPM2BStructSize<TPM2B_PUBLIC_KEY_RSA>(),
  };

  TPM2_RC rc = Tss2_Sys_RSA_Decrypt(
      tss_.GetSysContext(), key_handle, &sessions_data_, &data_in, &scheme,
      &outside_info, &data_out, &sessions_data_out_);
  assert(rc == TPM2_RC_SUCCESS);

  return std::vector<uint8_t>(data_out.buffer, data_out.buffer + data_out.size);
}

int App::EvictControl(uint32_t auth, uint32_t key_handle,
                      uint32_t persistent_handle) {
  LOG1("EvictControl %x %x\n", key_handle, persistent_handle);
  return Tss2_Sys_EvictControl(tss_.GetSysContext(), auth, key_handle,
                               &sessions_data_, persistent_handle,
                               &sessions_data_out_);
}

int App::NvDefineSpace(uint32_t nv_index, size_t data_size) {
  LOG1("NvDefineSpace %x %x\n", nv_index, data_size);
  TPM2B_AUTH auth = {};
  TPM2B_NV_PUBLIC public_info = {};
  public_info.size = sizeof(TPMS_NV_PUBLIC);
  public_info.nvPublic.nvIndex = nv_index;
  public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;
  public_info.nvPublic.attributes = BuildNvSpaceAttributes();
  public_info.nvPublic.authPolicy.size = 0;
  public_info.nvPublic.dataSize = data_size;
  return Tss2_Sys_NV_DefineSpace(tss_.GetSysContext(),
                                 /*authHandle=*/TPM2_RH_PLATFORM,
                                 &sessions_data_, &auth, &public_info,
                                 &sessions_data_out_);
}

int App::NvWrite(uint32_t nv_index, const std::vector<uint8_t> &data) {
  LOG1("NvWrite %x %x\n", nv_index, data.size());
  TPM2B_MAX_NV_BUFFER buffer = {};
  assert(data.size() <= TPM2_MAX_NV_BUFFER_SIZE);
  buffer.size = data.size();
  memcpy(buffer.buffer, data.data(), data.size());

  return Tss2_Sys_NV_Write(tss_.GetSysContext(),
                           /*authHandle=*/TPM2_RH_PLATFORM, nv_index,
                           &sessions_data_, &buffer,
                           /*offset=*/0, &sessions_data_out_);
}

NvReadPublicResult App::NvReadPublic(uint32_t nv_index) {
  LOG1("NvReadPublic %x\n", nv_index);

  TPM2B_NV_PUBLIC public_info = {};
  TPM2B_NAME name = {
      .size = TPM2BStructSize<TPM2B_NAME>(),
  };

  NvReadPublicResult result;
  result.rc = Tss2_Sys_NV_ReadPublic(tss_.GetSysContext(), nv_index,
                                     /*cmdAuthsArray=*/nullptr, &public_info,
                                     &name, /*rspAuthsArray=*/nullptr);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.data_size = public_info.nvPublic.dataSize;
  }
  return result;
}

NvReadResult App::NvRead(uint32_t nv_index, int size, int offset) {
  LOG1("NvRead %x %d %d\n", nv_index, size, offset);
  TPM2B_MAX_NV_BUFFER buffer = {
      .size = TPM2BStructSize<TPM2B_MAX_NV_BUFFER>(),
  };
  NvReadResult result;
  result.rc = Tss2_Sys_NV_Read(tss_.GetSysContext(), TPM2_RH_PLATFORM, nv_index,
                               &sessions_data_, size, offset, &buffer,
                               &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.data =
        std::vector<uint8_t>(buffer.buffer, buffer.buffer + buffer.size);
  }
  return result;
}

QuoteResult App::Quote(uint32_t key_handle, const std::string &nonce) {
  LOG1("Quote %x '%s'\n", key_handle, nonce.c_str());
  TPM2B_DATA qualifying_data = {};
  assert(nonce.size() < sizeof(qualifying_data.buffer));
  qualifying_data.size = nonce.size();
  memcpy(qualifying_data.buffer, nonce.data(), nonce.size());

  TPMT_SIG_SCHEME scheme = {};
  scheme.scheme = TPM2_ALG_NULL; // Use the key's signing scheme.

  TPML_PCR_SELECTION pcr_selection = {};

  pcr_selection.count = 1;
  pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
  pcr_selection.pcrSelections[0].sizeofSelect = 3;

  // Clear out PCR select bit field.
  pcr_selection.pcrSelections[0].pcrSelect[0] = 0;
  pcr_selection.pcrSelections[0].pcrSelect[1] = 0;
  pcr_selection.pcrSelections[0].pcrSelect[2] = 0;

  // Set the first four PCRs.
  pcr_selection.pcrSelections[0].pcrSelect[(0 / 8)] |= (1 << (0 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(1 / 8)] |= (1 << (1 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(2 / 8)] |= (1 << (2 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(3 / 8)] |= (1 << (3 % 8));

  TPM2B_ATTEST quoted = {
      .size = TPM2BStructSize<TPM2B_ATTEST>(),
  };

  TPMT_SIGNATURE signature = {};

  QuoteResult result;
  result.rc = Tss2_Sys_Quote(tss_.GetSysContext(), key_handle, &sessions_data_,
                             &qualifying_data, &scheme, &pcr_selection, &quoted,
                             &signature, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.sign_algo = signature.sigAlg;
    if (signature.sigAlg == TPM2_ALG_RSASSA) {
      result.hash_algo = signature.signature.rsassa.hash;
      result.rsa_ssa_sig =
          std::vector<uint8_t>(signature.signature.rsassa.sig.buffer,
                               signature.signature.rsassa.sig.buffer +
                                   signature.signature.rsassa.sig.size);
    }
    result.tpm2b_attest = std::vector<uint8_t>(
        quoted.attestationData, quoted.attestationData + quoted.size);
  }
  return result;
}

int App::HierarchyChangeAuth(int hierarchy, const std::string &auth_string) {
  LOG1("HierarchyChangeAuth %x '%s'\n", hierarchy, auth_string.c_str());
  TPM2B_AUTH auth = {};
  assert(auth_string.size() <= sizeof(auth.buffer));
  auth.size = auth_string.size();
  memcpy(auth.buffer, auth_string.c_str(), auth_string.size());
  return Tss2_Sys_HierarchyChangeAuth(tss_.GetSysContext(), hierarchy,
                                      &sessions_data_, &auth,
                                      &sessions_data_out_);
}

void App::SetAuthPassword(const std::string &auth_string) {
  LOG1("SetAuthPassword %s\n", auth_string.c_str());
  assert(auth_string.size() < sizeof(sessions_data_.auths[0].hmac.buffer));
  sessions_data_.auths[0].hmac.size = auth_string.size();
  memcpy(sessions_data_.auths[0].hmac.buffer, auth_string.c_str(),
         auth_string.size());
  SetSessionHandle(TPM2_RS_PW);
}

UnsealResult App::Unseal(uint32_t handle) {
  LOG1("Unseal %x\n", handle);
  TPM2B_SENSITIVE_DATA out_data = {
      .size = TPM2BStructSize<TPM2B_SENSITIVE_DATA>(),
  };
  UnsealResult result = {};
  result.rc = Tss2_Sys_Unseal(tss_.GetSysContext(), handle, &sessions_data_,
                              &out_data, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.sensitive_data =
        std::vector<uint8_t>(out_data.buffer, out_data.buffer + out_data.size);
  }
  return result;
}

StartAuthSessionResult App::StartAuthSession(bool is_trial) {
  LOG1("StartAuthSession %d\n", is_trial);
  TPM2B_NONCE nonce_caller = {
      .size = TPM2_SHA256_DIGEST_SIZE,
      .buffer = {0},
  };

  TPM2B_NONCE nonce_tpm = {
      .size = TPM2_SHA256_DIGEST_SIZE,
      .buffer = {0},
  };

  TPM2B_ENCRYPTED_SECRET encrypted_salt = {0};
  TPMI_SH_AUTH_SESSION session_handle = 0;
  TPM2_SE session_type = (is_trial ? TPM2_SE_TRIAL : TPM2_SE_POLICY);
  TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};

  StartAuthSessionResult result = {};
  result.rc = Tss2_Sys_StartAuthSession(
      tss_.GetSysContext(),
      /*tpmKey=*/TPM2_RH_NULL,
      /*bind=*/TPM2_RH_NULL,
      /*cmdAuthsArray=*/nullptr, &nonce_caller, &encrypted_salt, session_type,
      &symmetric, TPM2_ALG_SHA256, &session_handle, &nonce_tpm,
      /*rspAuthsArray=*/nullptr);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.handle = session_handle;
    result.nonce_tpm = std::vector<uint8_t>(nonce_tpm.buffer,
                                            nonce_tpm.buffer + nonce_tpm.size);
  }
  return result;
}

std::vector<uint8_t> App::PolicyGetDigest(uint32_t session_handle) {
  LOG1("PolicyGetDigest %x\n", session_handle);
  TPM2B_DIGEST digest = {
      TPM2BStructSize<TPM2B_DIGEST>(),
  };
  TPM2_RC rc = Tss2_Sys_PolicyGetDigest(tss_.GetSysContext(), session_handle,
                                        /*cmdAuthsArray=*/nullptr, &digest,
                                        /*rspAuthsArray=*/nullptr);
  assert(rc == TPM2_RC_SUCCESS);
  return std::vector<uint8_t>(digest.buffer, digest.buffer + digest.size);
}

void App::SetSessionHandle(uint32_t handle) {
  LOG1("SetSessionHandle %x\n", handle);
  sessions_data_.auths[0].sessionHandle = handle;
  sessions_data_.auths[0].sessionAttributes =
      (handle == TPM2_RS_PW ? 0 : TPMA_SESSION_CONTINUESESSION);
}

int App::PolicyPassword(uint32_t session_handle) {
  LOG1("PolicyPassword %x\n", session_handle);
  return Tss2_Sys_PolicyPassword(tss_.GetSysContext(), session_handle,
                                 /*cmdAuthsArray=*/nullptr,
                                 /*rspAuthsArray=*/nullptr);
}

int App::PolicyPCR(uint32_t session_handle,
                   const std::vector<uint8_t> &pcrs_digest) {
  LOG1("PolicyPCR %x\n", session_handle);
  TPML_PCR_SELECTION pcr_selection = {};

  pcr_selection.count = 1;
  pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
  pcr_selection.pcrSelections[0].sizeofSelect = 3;

  // Clear out PCR select bit field.
  pcr_selection.pcrSelections[0].pcrSelect[0] = 0;
  pcr_selection.pcrSelections[0].pcrSelect[1] = 0;
  pcr_selection.pcrSelections[0].pcrSelect[2] = 0;

  // Set the first four PCRs.
  pcr_selection.pcrSelections[0].pcrSelect[(0 / 8)] |= (1 << (0 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(1 / 8)] |= (1 << (1 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(2 / 8)] |= (1 << (2 % 8));
  pcr_selection.pcrSelections[0].pcrSelect[(3 / 8)] |= (1 << (3 % 8));

  TPM2B_DIGEST digest = {};
  assert(pcrs_digest.size() < sizeof(digest.buffer));
  digest.size = pcrs_digest.size();
  memcpy(digest.buffer, pcrs_digest.data(), pcrs_digest.size());

  return Tss2_Sys_PolicyPCR(tss_.GetSysContext(), session_handle,
                            /*cmdAuthsArray=*/nullptr, &digest, &pcr_selection,
                            /*rspAuthsArray=*/nullptr);
}

int App::PolicySecret(uint32_t auth_handle, uint32_t session_handle) {
  LOG1("PolicySecret %x\n", session_handle);
  int32_t expiration = 10;
  TPM2B_TIMEOUT timeout = {
      .size = TPM2BStructSize<TPM2B_TIMEOUT>(),
  };
  TPMT_TK_AUTH ticket = {};
  return Tss2_Sys_PolicySecret(tss_.GetSysContext(), auth_handle,
                               session_handle, &sessions_data_,
                               /*nonceTPM=*/nullptr, /*cpHashA=*/nullptr,
                               /*policyRef=*/nullptr, expiration, &timeout,
                               &ticket, &sessions_data_out_);
}

int App::DictionaryAttackLockReset() {
  LOG1("DictionaryAttackLockReset\n");
  return Tss2_Sys_DictionaryAttackLockReset(tss_.GetSysContext(),
                                            TPM2_RH_LOCKOUT, &sessions_data_,
                                            &sessions_data_out_);
}

ImportResult App::Import(uint32_t parent_handle,
                         const std::vector<uint8_t> &public_area,
                         const std::vector<uint8_t> &integrity_hmac,
                         const std::vector<uint8_t> &encrypted_private,
                         const std::vector<uint8_t> &encrypted_seed) {
  LOG1("Import %x\n", parent_handle);

  TPM2B_PUBLIC in_public = {
      .size = TPM2BStructSize<TPM2B_PUBLIC>(),
      .publicArea = TPM2BUnmarshal<TPMT_PUBLIC, Tss2_MU_TPMT_PUBLIC_Unmarshal>(
          public_area),
  };

  TPM2B_DIGEST mac = {};
  mac.size = integrity_hmac.size();
  assert(mac.size <= sizeof(mac.buffer));
  memcpy(mac.buffer, integrity_hmac.data(), mac.size);

  TPM2B_PRIVATE in_duplicate = {};
  size_t offset = 0;
  TSS2_RC rc = Tss2_MU_TPM2B_DIGEST_Marshal(
      &mac, in_duplicate.buffer, sizeof(in_duplicate.buffer), &offset);
  assert(rc == TPM2_RC_SUCCESS);
  in_duplicate.size += offset;
  memcpy(in_duplicate.buffer + in_duplicate.size, encrypted_private.data(),
         encrypted_private.size());
  in_duplicate.size += encrypted_private.size();

  TPM2B_ENCRYPTED_SECRET in_encrypted_secret = {};
  in_encrypted_secret.size = encrypted_seed.size();
  assert(in_encrypted_secret.size <= sizeof(in_encrypted_secret.secret));
  memcpy(in_encrypted_secret.secret, encrypted_seed.data(),
         in_encrypted_secret.size);

  TPMT_SYM_DEF_OBJECT in_sym_alg = {.algorithm = TPM2_ALG_NULL};
  TPM2B_PRIVATE out_private = {
      .size = TPM2BStructSize<TPM2B_PRIVATE>(),
  };

  ImportResult result = {};
  result.rc = Tss2_Sys_Import(tss_.GetSysContext(), parent_handle,
                              &sessions_data_, /*encryptionKey=*/nullptr,
                              &in_public, &in_duplicate, &in_encrypted_secret,
                              &in_sym_alg, &out_private, &sessions_data_out_);
  if (result.rc == TPM2_RC_SUCCESS) {
    result.tpm2b_private =
        TPM2BMarshal<TPM2B_PRIVATE, Tss2_MU_TPM2B_PRIVATE_Marshal>(
            &out_private);
    result.tpm2b_public =
        TPM2BMarshal<TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Marshal>(&in_public);
  }
  return result;
} // namespace tpm_js

} // namespace tpm_js
