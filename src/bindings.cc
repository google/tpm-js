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
#include "keyed_hash.h"
#include "simulator.h"
#include "util.h"

#include <emscripten/bind.h>
#include <emscripten/html5.h>

namespace e = emscripten;

// clang-format off
EMSCRIPTEN_BINDINGS(TPM) {
  e::function("SimPowerOn", &tpm_js::Simulator::PowerOn);
  e::function("SimPowerOff", &tpm_js::Simulator::PowerOff);
  e::function("SimManufactureReset", &tpm_js::Simulator::ManufactureReset);
  e::function("SimIsPoweredOn", &tpm_js::Simulator::IsPoweredOn);
  e::function("SimIsStarted", &tpm_js::Simulator::IsStarted);
  e::function("SimIsManufactured", &tpm_js::Simulator::IsManufactured);
  e::function("SimGetPcr", &tpm_js::Simulator::GetPcr);
  e::function("SimGetEndorsementSeed", &tpm_js::Simulator::GetEndorsementSeed);
  e::function("SimGetPlatformSeed", &tpm_js::Simulator::GetPlatformSeed);
  e::function("SimGetOwnerSeed", &tpm_js::Simulator::GetOwnerSeed);
  e::function("SimGetNullSeed", &tpm_js::Simulator::GetNullSeed);
  e::function("SimGetBootCounter", &tpm_js::Simulator::GetBootCounter);
  e::function("UtilUnmarshalAttestBuffer", &tpm_js::Util::UnmarshalAttestBuffer);
  e::function("UtilKDFa", &tpm_js::Util::KDFa);

  e::class_<tpm_js::App>("App")
    .constructor(&tpm_js::App::Get, e::allow_raw_pointers())
    .function("Startup", &tpm_js::App::Startup)
    .function("Shutdown", &tpm_js::App::Shutdown)
    .function("Clear", &tpm_js::App::Clear)
    .function("ExtendPcr", &tpm_js::App::ExtendPcr)
    .function("GetRandom", &tpm_js::App::GetRandom)
    .function("SelfTest", &tpm_js::App::SelfTest)
    .function("GetTpmProperties", &tpm_js::App::GetTpmProperties)
    .function("TestHashParam", &tpm_js::App::TestHashParam)
    .function("CreatePrimary", &tpm_js::App::CreatePrimary)
    .function("CreatePrimaryEndorsementKey", &tpm_js::App::CreatePrimaryEndorsementKey)
    .function("Create", &tpm_js::App::Create)
    .function("Load", &tpm_js::App::Load)
    .function("FlushContext", &tpm_js::App::FlushContext)
    .function("Sign", &tpm_js::App::Sign)
    .function("VerifySignature", &tpm_js::App::VerifySignature)
    .function("Encrypt", &tpm_js::App::Encrypt)
    .function("Decrypt", &tpm_js::App::Decrypt)
    .function("RSAEncrypt", &tpm_js::App::RSAEncrypt)
    .function("RSADecrypt", &tpm_js::App::RSADecrypt)
    .function("EvictControl", &tpm_js::App::EvictControl)
    .function("NvDefineSpace", &tpm_js::App::NvDefineSpace)
    .function("NvWrite", &tpm_js::App::NvWrite)
    .function("NvReadPublic", &tpm_js::App::NvReadPublic)
    .function("NvRead", &tpm_js::App::NvRead)
    .function("Quote", &tpm_js::App::Quote)
    .function("HierarchyChangeAuth", &tpm_js::App::HierarchyChangeAuth)
    .function("SetAuthPassword", &tpm_js::App::SetAuthPassword)
    .function("Unseal", &tpm_js::App::Unseal)
    .function("StartAuthSession", &tpm_js::App::StartAuthSession)
    .function("PolicyGetDigest", &tpm_js::App::PolicyGetDigest)
    .function("PolicyPassword", &tpm_js::App::PolicyPassword)
    .function("PolicyPCR", &tpm_js::App::PolicyPCR)
    .function("PolicySecret", &tpm_js::App::PolicySecret)
    .function("SetSessionHandle", &tpm_js::App::SetSessionHandle)
    .function("DictionaryAttackLockReset", &tpm_js::App::DictionaryAttackLockReset)
    .function("Import", &tpm_js::App::Import)
  ;

  e::value_object<tpm_js::TpmProperties>("TpmProperties")
    .field("spec_version", &tpm_js::TpmProperties::spec_version)
    .field("manufacturer_id", &tpm_js::TpmProperties::manufacturer_id)
  ;

  e::value_object<tpm_js::CreatePrimaryResult>("CreatePrimaryResult")
    .field("rc", &tpm_js::CreatePrimaryResult::rc)
    .field("handle", &tpm_js::CreatePrimaryResult::handle)
    .field("rsa_public_n", &tpm_js::CreatePrimaryResult::rsa_public_n)
    .field("ecc_public_x", &tpm_js::CreatePrimaryResult::ecc_public_x)
    .field("ecc_public_y", &tpm_js::CreatePrimaryResult::ecc_public_y)
    .field("ecc_curve_id", &tpm_js::CreatePrimaryResult::ecc_curve_id)
    .field("name", &tpm_js::CreatePrimaryResult::name)
    .field("parent_name", &tpm_js::CreatePrimaryResult::parent_name)
    .field("parent_qualified_name", &tpm_js::CreatePrimaryResult::parent_qualified_name)
  ;

  e::value_object<tpm_js::CreateResult>("CreateResult")
    .field("rc", &tpm_js::CreateResult::rc)
    .field("tpm2b_private", &tpm_js::CreateResult::tpm2b_private)
    .field("tpm2b_public", &tpm_js::CreateResult::tpm2b_public)
    .field("rsa_public_n", &tpm_js::CreateResult::rsa_public_n)
    .field("ecc_public_x", &tpm_js::CreateResult::ecc_public_x)
    .field("ecc_public_y", &tpm_js::CreateResult::ecc_public_y)
    .field("ecc_curve_id", &tpm_js::CreateResult::ecc_curve_id)
    .field("parent_name", &tpm_js::CreateResult::parent_name)
    .field("parent_qualified_name", &tpm_js::CreateResult::parent_qualified_name)
  ;

  e::value_object<tpm_js::LoadResult>("LoadResult")
    .field("rc", &tpm_js::LoadResult::rc)
    .field("handle", &tpm_js::LoadResult::handle)
    .field("name", &tpm_js::LoadResult::name)
  ;

  e::value_object<tpm_js::SignResult>("SignResult")
    .field("rc", &tpm_js::SignResult::rc)
    .field("sign_algo", &tpm_js::SignResult::sign_algo)
    .field("hash_algo", &tpm_js::SignResult::hash_algo)
    .field("rsa_ssa_sig", &tpm_js::SignResult::rsa_ssa_sig)
    .field("ecdsa_r", &tpm_js::SignResult::ecdsa_r)
    .field("ecdsa_s", &tpm_js::SignResult::ecdsa_s)
  ;

  e::value_object<tpm_js::NvReadPublicResult>("NvReadPublicResult")
    .field("rc", &tpm_js::NvReadPublicResult::rc)
    .field("data_size", &tpm_js::NvReadPublicResult::data_size)
  ;

  e::value_object<tpm_js::NvReadResult>("NvReadResult")
    .field("rc", &tpm_js::NvReadResult::rc)
    .field("data", &tpm_js::NvReadResult::data)
  ;

  e::value_object<tpm_js::QuoteResult>("QuoteResult")
    .field("rc", &tpm_js::QuoteResult::rc)
    .field("sign_algo", &tpm_js::QuoteResult::sign_algo)
    .field("hash_algo", &tpm_js::QuoteResult::hash_algo)
    .field("rsa_ssa_sig", &tpm_js::QuoteResult::rsa_ssa_sig)
    .field("tpm2b_attest", &tpm_js::QuoteResult::tpm2b_attest)
  ;

  e::value_object<tpm_js::AttestInfo>("AttestInfo")
    .field("rc", &tpm_js::AttestInfo::rc)
    .field("magic", &tpm_js::AttestInfo::magic)
    .field("type", &tpm_js::AttestInfo::type)
    .field("signer_qualified_name", &tpm_js::AttestInfo::signer_qualified_name)
    .field("nonce", &tpm_js::AttestInfo::nonce)
    .field("selected_pcr_digest", &tpm_js::AttestInfo::selected_pcr_digest)
  ;

  e::value_object<tpm_js::UnsealResult>("UnsealResult")
    .field("rc", &tpm_js::UnsealResult::rc)
    .field("sensitive_data", &tpm_js::UnsealResult::sensitive_data)
  ;

  e::value_object<tpm_js::StartAuthSessionResult>("StartAuthSessionResult")
    .field("rc", &tpm_js::StartAuthSessionResult::rc)
    .field("handle", &tpm_js::StartAuthSessionResult::handle)
    .field("nonce_tpm", &tpm_js::StartAuthSessionResult::nonce_tpm)
  ;

  e::value_object<tpm_js::ImportResult>("ImportResult")
    .field("rc", &tpm_js::ImportResult::rc)
    .field("tpm2b_private", &tpm_js::ImportResult::tpm2b_private)
    .field("tpm2b_public", &tpm_js::ImportResult::tpm2b_public)
  ;

  e::class_<tpm_js::KeyedHash>("KeyedHash")
    .constructor<const std::string&>()
    .function("GetEncodedPrivate", &tpm_js::KeyedHash::GetEncodedPrivate)
    .function("GetEncodedPublic", &tpm_js::KeyedHash::GetEncodedPublic)
    .function("GetEncodedPublicName", &tpm_js::KeyedHash::GetEncodedPublicName)
  ;

  e::register_vector<unsigned char>("StdVectorOfBytes");
}
// clang-format on
