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

#include "tss_adapter.h"

namespace tpm_js {

struct TpmProperties {
  int spec_version;
  std::string manufacturer_id;
};

struct CreatePrimaryResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  // Loaded object handle.
  uint32_t handle;
  // RSA public key material (n). Valid only if type == TPM2_ALG_RSA.
  std::vector<uint8_t> rsa_public_n;
  // ECC public key material (affine coordinates). Valid only if type ==
  // TPM2_ALG_ECC.
  std::vector<uint8_t> ecc_public_x;
  std::vector<uint8_t> ecc_public_y;
  int ecc_curve_id;
  // Copy of TPM2B_NAME. This is the hash of the canonical form of
  // tpm2b_out_public.
  std::vector<uint8_t> name;
  // Parent information from TPM2B_CREATION_DATA.
  std::vector<uint8_t> parent_name;
  std::vector<uint8_t> parent_qualified_name;
};

struct CreateResult {
  int rc;
  // Copy of TPM2B_PRIVATE buffer. Can later be used with Load.
  std::vector<uint8_t> tpm2b_private;
  // Copy of TPM2B_PUBLIC buffer. Can later be used with Load.
  std::vector<uint8_t> tpm2b_public;
  // RSA public key material (n). Valid only if type == TPM2_ALG_RSA.
  std::vector<uint8_t> rsa_public_n;
  // ECC public key material (affine coordinates). Valid only if type ==
  // TPM2_ALG_ECC.
  std::vector<uint8_t> ecc_public_x;
  std::vector<uint8_t> ecc_public_y;
  int ecc_curve_id;
  // Parent information from TPM2B_CREATION_DATA.
  std::vector<uint8_t> parent_name;
  std::vector<uint8_t> parent_qualified_name;
};

struct LoadResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  // Loaded object handle.
  uint32_t handle;
  // Copy of TPM2B_NAME. This is the hash of the canonical form of
  // tpm2b_out_public.
  std::vector<uint8_t> name;
};

struct SignResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  int sign_algo;
  int hash_algo;
  // RSA signature. Valid only if sign_algo == TPM2_ALG_RSASSA.
  std::vector<uint8_t> rsa_ssa_sig;
  // ECDSA signature. Valid only if sign_algo == TPM2_ALG_ECDSA.
  std::vector<uint8_t> ecdsa_r;
  std::vector<uint8_t> ecdsa_s;
};

struct NvReadPublicResult {
  int rc;
  int data_size;
};

struct NvReadResult {
  int rc;
  std::vector<uint8_t> data;
};

struct QuoteResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  int sign_algo;
  int hash_algo;
  // RSA signature. Valid only if sign_algo == TPM2_ALG_RSASSA.
  std::vector<uint8_t> rsa_ssa_sig;
  // Wire representation of TPMS_ATTEST structure.
  // The signature is over this buffer.
  std::vector<uint8_t> tpm2b_attest;
};

struct UnsealResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  std::vector<uint8_t> sensitive_data;
};

struct StartAuthSessionResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  uint32_t handle;
  std::vector<uint8_t> nonce_tpm;
};

struct ImportResult {
  int rc;
  // Following fields are only valid if rc == TPM2_RC_SUCCESS.
  // Copy of TPM2B_PRIVATE buffer. Can later be used with Load.
  std::vector<uint8_t> tpm2b_private;
  // Copy of TPM2B_PUBLIC buffer. Can later be used with Load.
  std::vector<uint8_t> tpm2b_public;
};

class App {
public:
  static App *Get();
  ~App();

  // Calls Tss2_Sys_Startup with TPM2_SU_CLEAR.
  int Startup();

  // Calls Tss2_Sys_Shutdown with TPM2_SU_CLEAR.
  int Shutdown();

  // Calls Tss2_Sys_Clear with TPM2_RH_PLATFORM.
  int Clear();

  // Calls Tss2_Sys_PCR_Extend with the SHA256 digest of str.
  int ExtendPcr(int pcr, const std::string &str);

  // Calls Tss2_Sys_GetRandom with num_bytes.
  std::vector<uint8_t> GetRandom(int num_bytes);

  // Calls Tss2_Sys_SelfTest.
  int SelfTest();

  // Reads TPM properties by calling Tss2_Sys_GetCapability with
  // TPM2_CAP_TPM_PROPERTIES.
  TpmProperties GetTpmProperties();

  // Calls Tss2_Sys_TestParms with TPM2_ALG_KEYEDHASH and given HASH algorithm.
  int TestHashParam(int hash_algo);

  // Calls Tss2_Sys_CreatePrimary.
  // hierarchy = {TPM2_RH_NULL, TPM2_RH_ENDORSEMENT, TPM2_RH_PLATFORM,
  // TPM2_RH_OWNER}.
  // type = {TPM2_ALG_RSA, TPM2_ALG_ECC, TPM2_ALG_SYMCIPHER,
  // TPM2_ALG_KEYEDHASH}.
  // restricted means the key is used only to sign internal TPM data.
  CreatePrimaryResult CreatePrimary(int hierarchy, int type, int restricted,
                                    int decrypt, int sign,
                                    const std::string &unique,
                                    const std::string &user_auth,
                                    const std::string &sensitive_data,
                                    const std::vector<uint8_t> &auth_policy);

  // Creates a primary endorsement key, derived from the default TGC template.
  CreatePrimaryResult CreatePrimaryEndorsementKey();

  // Calls Tss2_Sys_Create.
  // type = {TPM2_ALG_RSA, TPM2_ALG_ECC, TPM2_ALG_SYMCIPHER,
  // TPM2_ALG_KEYEDHASH}.
  // restricted means the key is used only to sign internal TPM data.
  CreateResult Create(uint32_t parent_handle, int type, int restricted,
                      int decrypt, int sign, const std::string &user_auth,
                      const std::string &sensitive_data,
                      const std::vector<uint8_t> &auth_policy);

  // Calls Tss2_Sys_Load.
  LoadResult Load(uint32_t parent_handle,
                  const std::vector<uint8_t> &tpm2b_private,
                  const std::vector<uint8_t> &tpm2b_public);

  // Calls Tss2_Sys_FlushContext.
  int FlushContext(uint32_t handle);

  // Calls Tss2_Sys_Sign with the SHA256 digest of str.
  // type = {TPM2_ALG_RSA, TPM2_ALG_ECC}.
  SignResult Sign(uint32_t key_handle, int type, const std::string &str);

  // Verifies the SHA256 digest of str against the signature.
  int VerifySignature(uint32_t key_handle, const std::string &str,
                      const SignResult &in_signature);

  // Calls Tss2_Sys_EncryptDecrypt.
  // key_handle should be a handle of a loaded TPM2_ALG_SYMCIPHER key.
  std::vector<uint8_t> Encrypt(uint32_t key_handle,
                               const std::vector<uint8_t> &message);

  // Calls Tss2_Sys_EncryptDecrypt.
  // key_handle should be a handle of a loaded TPM2_ALG_SYMCIPHER key.
  std::vector<uint8_t> Decrypt(uint32_t key_handle,
                               const std::vector<uint8_t> &message);

  // Calls Tss2_Sys_RSA_Encrypt.
  // key_handle should be a handle of a loaded TPM2_ALG_RSA key.
  std::vector<uint8_t> RSAEncrypt(uint32_t key_handle,
                                  const std::vector<uint8_t> &message);

  // Calls Tss2_Sys_RSA_Decrypt.
  // key_handle should be a handle of a loaded TPM2_ALG_RSA key.
  std::vector<uint8_t> RSADecrypt(uint32_t key_handle,
                                  const std::vector<uint8_t> &message);

  // Calls Tss2_Sys_EventControl.
  int EvictControl(uint32_t auth, uint32_t key_handle,
                   uint32_t persistent_handle);

  // Calls Tss2_Sys_NV_DefineSpace.
  int NvDefineSpace(uint32_t nv_index, size_t data_size);

  // Calls Tss2_Sys_NV_Write.
  int NvWrite(uint32_t nv_index, const std::vector<uint8_t> &data);

  // Calls Tss2_Sys_NV_ReadPublic.
  NvReadPublicResult NvReadPublic(uint32_t nv_index);

  // Calls Tss2_Sys_NV_Read.
  NvReadResult NvRead(uint32_t nv_index, int size, int offset);

  // Calls Tss2_Sys_Quote. Signs the SHA256 digest of PCR0, PCR1, PCR2 and PCR3.
  QuoteResult Quote(uint32_t key_handle, const std::string &nonce);

  // Calls Tss2_Sys_HierarchyChangeAuth.
  int HierarchyChangeAuth(int hierarchy, const std::string &auth_string);

  // Sets hmac value of sessions_data_out_.auths[0].
  void SetAuthPassword(const std::string &auth_string);

  // Calls Tss2_Sys_Unseal.
  UnsealResult Unseal(uint32_t handle);

  // Calls Tss2_Sys_StartAuthSession.
  StartAuthSessionResult StartAuthSession(bool is_trial);

  // Calls Tss2_Sys_PolicyGetDigest.
  std::vector<uint8_t> PolicyGetDigest(uint32_t session_handle);

  // Calls Tss2_Sys_PolicyPassword.
  int PolicyPassword(uint32_t session_handle);

  // Calls Tss2_Sys_PolicyPCR.
  // TPML_PCR_SELECTION selects the first four PCRs.
  int PolicyPCR(uint32_t session_handle,
                const std::vector<uint8_t> &pcrs_digest);

  // Calls Tss2_Sys_PolicySecret.
  int PolicySecret(uint32_t auth_handle, uint32_t session_handle);

  // Sets handle value of sessions_data_out_.auths[0].
  void SetSessionHandle(uint32_t handle);

  // Calls Tss2_Sys_DictionaryAttackLockReset.
  int DictionaryAttackLockReset();

  // Calls Tss2_Sys_Import.
  ImportResult Import(uint32_t parent_handle,
                      const std::vector<uint8_t> &public_area,
                      const std::vector<uint8_t> &integrity_hmac,
                      const std::vector<uint8_t> &encrypted_private,
                      const std::vector<uint8_t> &encrypted_seed);

private:
  App();

  // Clears sessions_data_.
  void ClearSessionData();

  // Calls Tss2_Sys_GetCapability with the given capability and property.
  TPMS_CAPABILITY_DATA GetCapability(TPM2_CAP capability, UINT32 property);

  // Calls Tss2_Sys_EncryptDecrypt.
  std::vector<uint8_t> EncryptDecrypt(uint32_t key_handle,
                                      const std::vector<uint8_t> &message,
                                      bool decrypt);

  // Calls Tss2_Sys_CreatePrimary.
  CreatePrimaryResult
  CreatePrimaryFromTemplate(int hierarchy,
                            const TPM2B_SENSITIVE_CREATE &in_sensitive,
                            const TPM2B_PUBLIC &in_public);

  // Maintains TSS2_SYS_CONTEXT passed to Tss2_Sys_* functions.
  TssAdapter tss_;

  // Session data is used across different TPM calls.
  TSS2L_SYS_AUTH_COMMAND sessions_data_;
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out_;
};

} // namespace tpm_js
