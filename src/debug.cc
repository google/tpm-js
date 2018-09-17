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

#include "debug.h"

#include <unordered_map>

#include "tss2_tpm2_types.h"

namespace tpm_js {

std::string GetTpmCommandName(uint32_t code) {
  static const std::unordered_map<uint32_t, std::string> *const kMapping =
      new std::unordered_map<uint32_t, std::string>{
          {TPM2_CC_NV_UndefineSpaceSpecial, "TPM2_CC_NV_UndefineSpaceSpecial"},
          {TPM2_CC_EvictControl, "TPM2_CC_EvictControl"},
          {TPM2_CC_HierarchyControl, "TPM2_CC_HierarchyControl"},
          {TPM2_CC_NV_UndefineSpace, "TPM2_CC_NV_UndefineSpace"},
          {TPM2_CC_ChangeEPS, "TPM2_CC_ChangeEPS"},
          {TPM2_CC_ChangePPS, "TPM2_CC_ChangePPS"},
          {TPM2_CC_Clear, "TPM2_CC_Clear"},
          {TPM2_CC_ClearControl, "TPM2_CC_ClearControl"},
          {TPM2_CC_ClockSet, "TPM2_CC_ClockSet"},
          {TPM2_CC_HierarchyChangeAuth, "TPM2_CC_HierarchyChangeAuth"},
          {TPM2_CC_NV_DefineSpace, "TPM2_CC_NV_DefineSpace"},
          {TPM2_CC_PCR_Allocate, "TPM2_CC_PCR_Allocate"},
          {TPM2_CC_PCR_SetAuthPolicy, "TPM2_CC_PCR_SetAuthPolicy"},
          {TPM2_CC_PP_Commands, "TPM2_CC_PP_Commands"},
          {TPM2_CC_SetPrimaryPolicy, "TPM2_CC_SetPrimaryPolicy"},
          // {TPM2_CC_FieldUpgradeStart, "TPM2_CC_FieldUpgradeStart"},
          {TPM2_CC_ClockRateAdjust, "TPM2_CC_ClockRateAdjust"},
          {TPM2_CC_CreatePrimary, "TPM2_CC_CreatePrimary"},
          {TPM2_CC_NV_GlobalWriteLock, "TPM2_CC_NV_GlobalWriteLock"},
          {TPM2_CC_GetCommandAuditDigest, "TPM2_CC_GetCommandAuditDigest"},
          {TPM2_CC_NV_Increment, "TPM2_CC_NV_Increment"},
          {TPM2_CC_NV_SetBits, "TPM2_CC_NV_SetBits"},
          {TPM2_CC_NV_Extend, "TPM2_CC_NV_Extend"},
          {TPM2_CC_NV_Write, "TPM2_CC_NV_Write"},
          {TPM2_CC_NV_WriteLock, "TPM2_CC_NV_WriteLock"},
          {TPM2_CC_DictionaryAttackLockReset,
           "TPM2_CC_DictionaryAttackLockReset"},
          {TPM2_CC_DictionaryAttackParameters,
           "TPM2_CC_DictionaryAttackParameters"},
          {TPM2_CC_NV_ChangeAuth, "TPM2_CC_NV_ChangeAuth"},
          {TPM2_CC_PCR_Event, "TPM2_CC_PCR_Event"},
          {TPM2_CC_PCR_Reset, "TPM2_CC_PCR_Reset"},
          {TPM2_CC_SequenceComplete, "TPM2_CC_SequenceComplete"},
          {TPM2_CC_SetAlgorithmSet, "TPM2_CC_SetAlgorithmSet"},
          {TPM2_CC_SetCommandCodeAuditStatus,
           "TPM2_CC_SetCommandCodeAuditStatus"},
          // {TPM2_CC_FieldUpgradeData, "TPM2_CC_FieldUpgradeData"},
          {TPM2_CC_IncrementalSelfTest, "TPM2_CC_IncrementalSelfTest"},
          {TPM2_CC_SelfTest, "TPM2_CC_SelfTest"},
          {TPM2_CC_Startup, "TPM2_CC_Startup"},
          {TPM2_CC_Shutdown, "TPM2_CC_Shutdown"},
          {TPM2_CC_StirRandom, "TPM2_CC_StirRandom"},
          {TPM2_CC_ActivateCredential, "TPM2_CC_ActivateCredential"},
          {TPM2_CC_Certify, "TPM2_CC_Certify"},
          {TPM2_CC_PolicyNV, "TPM2_CC_PolicyNV"},
          {TPM2_CC_CertifyCreation, "TPM2_CC_CertifyCreation"},
          {TPM2_CC_Duplicate, "TPM2_CC_Duplicate"},
          {TPM2_CC_GetTime, "TPM2_CC_GetTime"},
          {TPM2_CC_GetSessionAuditDigest, "TPM2_CC_GetSessionAuditDigest"},
          {TPM2_CC_NV_Read, "TPM2_CC_NV_Read"},
          {TPM2_CC_NV_ReadLock, "TPM2_CC_NV_ReadLock"},
          {TPM2_CC_ObjectChangeAuth, "TPM2_CC_ObjectChangeAuth"},
          {TPM2_CC_PolicySecret, "TPM2_CC_PolicySecret"},
          {TPM2_CC_Rewrap, "TPM2_CC_Rewrap"},
          {TPM2_CC_Create, "TPM2_CC_Create"},
          {TPM2_CC_ECDH_ZGen, "TPM2_CC_ECDH_ZGen"},
          {TPM2_CC_HMAC, "TPM2_CC_HMAC"},
          {TPM2_CC_Import, "TPM2_CC_Import"},
          {TPM2_CC_Load, "TPM2_CC_Load"},
          {TPM2_CC_Quote, "TPM2_CC_Quote"},
          {TPM2_CC_RSA_Decrypt, "TPM2_CC_RSA_Decrypt"},
          {TPM2_CC_HMAC_Start, "TPM2_CC_HMAC_Start"},
          {TPM2_CC_SequenceUpdate, "TPM2_CC_SequenceUpdate"},
          {TPM2_CC_Sign, "TPM2_CC_Sign"},
          {TPM2_CC_Unseal, "TPM2_CC_Unseal"},
          {TPM2_CC_PolicySigned, "TPM2_CC_PolicySigned"},
          {TPM2_CC_ContextLoad, "TPM2_CC_ContextLoad"},
          {TPM2_CC_ContextSave, "TPM2_CC_ContextSave"},
          {TPM2_CC_ECDH_KeyGen, "TPM2_CC_ECDH_KeyGen"},
          {TPM2_CC_EncryptDecrypt, "TPM2_CC_EncryptDecrypt"},
          {TPM2_CC_FlushContext, "TPM2_CC_FlushContext"},
          {TPM2_CC_LoadExternal, "TPM2_CC_LoadExternal"},
          {TPM2_CC_MakeCredential, "TPM2_CC_MakeCredential"},
          {TPM2_CC_NV_ReadPublic, "TPM2_CC_NV_ReadPublic"},
          {TPM2_CC_PolicyAuthorize, "TPM2_CC_PolicyAuthorize"},
          {TPM2_CC_PolicyAuthValue, "TPM2_CC_PolicyAuthValue"},
          {TPM2_CC_PolicyCommandCode, "TPM2_CC_PolicyCommandCode"},
          {TPM2_CC_PolicyCounterTimer, "TPM2_CC_PolicyCounterTimer"},
          {TPM2_CC_PolicyCpHash, "TPM2_CC_PolicyCpHash"},
          {TPM2_CC_PolicyLocality, "TPM2_CC_PolicyLocality"},
          {TPM2_CC_PolicyNameHash, "TPM2_CC_PolicyNameHash"},
          {TPM2_CC_PolicyOR, "TPM2_CC_PolicyOR"},
          {TPM2_CC_PolicyTicket, "TPM2_CC_PolicyTicket"},
          {TPM2_CC_ReadPublic, "TPM2_CC_ReadPublic"},
          {TPM2_CC_RSA_Encrypt, "TPM2_CC_RSA_Encrypt"},
          {TPM2_CC_StartAuthSession, "TPM2_CC_StartAuthSession"},
          {TPM2_CC_VerifySignature, "TPM2_CC_VerifySignature"},
          {TPM2_CC_ECC_Parameters, "TPM2_CC_ECC_Parameters"},
          // {TPM2_CC_FirmwareRead, "TPM2_CC_FirmwareRead"},
          {TPM2_CC_GetCapability, "TPM2_CC_GetCapability"},
          {TPM2_CC_GetRandom, "TPM2_CC_GetRandom"},
          {TPM2_CC_GetTestResult, "TPM2_CC_GetTestResult"},
          {TPM2_CC_Hash, "TPM2_CC_Hash"},
          {TPM2_CC_PCR_Read, "TPM2_CC_PCR_Read"},
          {TPM2_CC_PolicyPCR, "TPM2_CC_PolicyPCR"},
          {TPM2_CC_PolicyRestart, "TPM2_CC_PolicyRestart"},
          {TPM2_CC_ReadClock, "TPM2_CC_ReadClock"},
          {TPM2_CC_PCR_Extend, "TPM2_CC_PCR_Extend"},
          {TPM2_CC_PCR_SetAuthValue, "TPM2_CC_PCR_SetAuthValue"},
          {TPM2_CC_NV_Certify, "TPM2_CC_NV_Certify"},
          {TPM2_CC_EventSequenceComplete, "TPM2_CC_EventSequenceComplete"},
          {TPM2_CC_HashSequenceStart, "TPM2_CC_HashSequenceStart"},
          {TPM2_CC_PolicyPhysicalPresence, "TPM2_CC_PolicyPhysicalPresence"},
          {TPM2_CC_PolicyDuplicationSelect, "TPM2_CC_PolicyDuplicationSelect"},
          {TPM2_CC_PolicyGetDigest, "TPM2_CC_PolicyGetDigest"},
          {TPM2_CC_TestParms, "TPM2_CC_TestParms"},
          {TPM2_CC_Commit, "TPM2_CC_Commit"},
          {TPM2_CC_PolicyPassword, "TPM2_CC_PolicyPassword"},
          {TPM2_CC_ZGen_2Phase, "TPM2_CC_ZGen_2Phase"},
          {TPM2_CC_EC_Ephemeral, "TPM2_CC_EC_Ephemeral"},
          {TPM2_CC_PolicyNvWritten, "TPM2_CC_PolicyNvWritten"},
          {TPM2_CC_PolicyTemplate, "TPM2_CC_PolicyTemplate"},
          {TPM2_CC_CreateLoaded, "TPM2_CC_CreateLoaded"},
          {TPM2_CC_PolicyAuthorizeNV, "TPM2_CC_PolicyAuthorizeNV"},
          {TPM2_CC_EncryptDecrypt2, "TPM2_CC_EncryptDecrypt2"},
          {TPM2_CC_Vendor_TCG_Test, "TPM2_CC_Vendor_TCG_Test"}};
  auto iter = kMapping->find(code);
  if (iter == kMapping->end()) {
    return "Unknown";
  }
  return iter->second;
}

} // namespace tpm_js
