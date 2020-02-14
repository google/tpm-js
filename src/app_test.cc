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
#include "simulator.h"
#include "util.h"

#include <gtest/gtest.h>

namespace tpm_js {
namespace {

TEST(AppTestNoFixture, TestStartup) {
  App *app = App::Get();
  Simulator::PowerOn();
  Simulator::ManufactureReset();
  EXPECT_EQ(Simulator::IsStarted(), false);
  EXPECT_EQ(0, Simulator::GetBootCounter());
  EXPECT_EQ(TPM2_RC_SUCCESS, app->Startup());
  EXPECT_EQ(Simulator::IsStarted(), true);
  EXPECT_EQ(1, Simulator::GetBootCounter());
}

class AppTest : public ::testing::Test {
protected:
  void SetUp() override {
    std::cout << "Setup: resetting simulator\n";
    Simulator::PowerOff();
    Simulator::PowerOn();
    Simulator::ManufactureReset();
    App *app = App::Get();
    EXPECT_EQ(TPM2_RC_SUCCESS, app->Startup());
    std::cout << "Setup: done\n";
  }

  void TearDown() override {
    std::cout << "Teadown: shutting down simulator\n";
    Simulator::PowerOff();
    std::cout << "Teadown: down\n";
  }
};

TEST_F(AppTest, TestPcrExtend) {
  App *app = App::Get();
  const std::vector<uint8_t> kZeros(32, 0);
  EXPECT_EQ(kZeros, Simulator::GetPcr(1));
  EXPECT_EQ(TPM2_RC_SUCCESS, app->ExtendPcr(1, "hello"));
  EXPECT_NE(kZeros, Simulator::GetPcr(1));
}

TEST_F(AppTest, TestGetRandom) {
  App *app = App::Get();
  const std::vector<uint8_t> before = app->GetRandom(10);
  EXPECT_EQ(before.size(), 10);
  const std::vector<uint8_t> after = app->GetRandom(10);
  EXPECT_EQ(after.size(), 10);
  EXPECT_NE(before, after);
}

TEST_F(AppTest, TestSelfTest) {
  App *app = App::Get();
  EXPECT_EQ(TPM2_RC_SUCCESS, app->SelfTest());
}

TEST_F(AppTest, TestGetTpmProperties) {
  App *app = App::Get();
  auto properties = app->GetTpmProperties();
  EXPECT_EQ(146, properties.spec_version);
  EXPECT_EQ("IBM ", properties.manufacturer_id);
}

TEST_F(AppTest, TestClear) {
  App *app = App::Get();
  auto oseed_before = Simulator::GetOwnerSeed();
  EXPECT_EQ(TPM2_RC_SUCCESS, app->Clear());
  auto oseed_after = Simulator::GetOwnerSeed();
  EXPECT_NE(oseed_before, oseed_after);
}

TEST_F(AppTest, TestHashParam) {
  App *app = App::Get();
  EXPECT_EQ(TPM2_RC_SUCCESS, app->TestHashParam(TPM2_ALG_SHA1));
  EXPECT_EQ(TPM2_RC_SUCCESS, app->TestHashParam(TPM2_ALG_SHA256));
  EXPECT_EQ(TPM2_RC_P + TPM2_RC_1 + TPM2_RC_HASH,
            app->TestHashParam(TPM2_ALG_SHA512));
}

TEST_F(AppTest, TestCreatePrimarySYM) {
  App *app = App::Get();
  CreatePrimaryResult result =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_SYMCIPHER, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
}

TEST_F(AppTest, TestCreatePrimaryHASH) {
  App *app = App::Get();
  CreatePrimaryResult result =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_KEYEDHASH, /*restricted=*/0,
                         /*decrypt=*/0, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"secret-data",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
}

TEST_F(AppTest, TestCreatePrimarySYMDifferentTemplates) {
  App *app = App::Get();
  CreatePrimaryResult k1 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_SYMCIPHER, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"hello",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k1.rc);

  CreatePrimaryResult k2 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_SYMCIPHER, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"world",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k2.rc);
  EXPECT_NE(k1.name, k2.name);
}

TEST_F(AppTest, TestCreatePrimaryEndorsementKey) {
  App *app = App::Get();
  CreatePrimaryResult result = app->CreatePrimaryEndorsementKey();
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.rsa_public_n.size(), 2048 / 8);
  EXPECT_EQ(result.ecc_public_x.size(), 0);
  EXPECT_EQ(result.ecc_public_y.size(), 0);
  EXPECT_EQ(result.ecc_curve_id, 0);
  const std::vector<uint8_t> kEndorsementName = {0x40, 0x00, 0x00, 0x0B};
  EXPECT_EQ(result.parent_name, kEndorsementName);
  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(result.handle));
}

TEST_F(AppTest, TestCreatePrimaryRSA) {
  App *app = App::Get();
  CreatePrimaryResult result =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.rsa_public_n.size(), 2048 / 8);
  EXPECT_EQ(result.ecc_public_x.size(), 0);
  EXPECT_EQ(result.ecc_public_y.size(), 0);
  EXPECT_EQ(result.ecc_curve_id, 0);
  const std::vector<uint8_t> kOwnerName = {0x40, 0x00, 0x00, 0x01};
  EXPECT_EQ(result.parent_name, kOwnerName);
  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(result.handle));
}

TEST_F(AppTest, TestCreatePrimaryRSADifferentTemplates) {
  App *app = App::Get();
  CreatePrimaryResult k1 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"hello",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k1.rc);

  CreatePrimaryResult k2 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"world",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k2.rc);
  EXPECT_NE(k1.name, k2.name);
}

TEST_F(AppTest, TestCreatePrimaryECC) {
  App *app = App::Get();
  CreatePrimaryResult result =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.rsa_public_n.size(), 0);
  EXPECT_GT(result.ecc_public_x.size(), 0);
  EXPECT_GT(result.ecc_public_y.size(), 0);
  EXPECT_EQ(result.ecc_curve_id, TPM2_ECC_NIST_P256);
  const std::vector<uint8_t> kOwnerName = {0x40, 0x00, 0x00, 0x01};
  EXPECT_EQ(result.parent_name, kOwnerName);
  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(result.handle));
}

TEST_F(AppTest, TestCreatePrimaryECCDifferentTemplates) {
  App *app = App::Get();
  CreatePrimaryResult k1 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"hello",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k1.rc);

  CreatePrimaryResult k2 =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"world",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, k2.rc);
  EXPECT_NE(k1.name, k2.name);
}

TEST_F(AppTest, TestCreateSYM) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_SYMCIPHER, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result = app->Create(primary.handle, TPM2_ALG_SYMCIPHER,
                                    /*restricted=*/1, /*decrypt=*/1,
                                    /*sign=*/0,
                                    /*user_auth=*/"", /*sensitive_data=*/"",
                                    /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.parent_name, primary.name);
}

TEST_F(AppTest, TestCreateRSA) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result =
      app->Create(primary.handle, TPM2_ALG_RSA, /*restricted=*/1, /*decrypt=*/1,
                  /*sign=*/0,
                  /*user_auth=*/"", /*sensitive_data=*/"", /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.parent_name, primary.name);
}

TEST_F(AppTest, TestCreateFailsForRSASigningKey) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result =
      app->Create(primary.handle, TPM2_ALG_RSA, /*restricted=*/1, /*decrypt=*/1,
                  /*sign=*/0,
                  /*user_auth=*/"", /*sensitive_data=*/"", /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_TYPE, result.rc);
}

TEST_F(AppTest, TestCreateECC) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result =
      app->Create(primary.handle, TPM2_ALG_ECC, /*restricted=*/1, /*decrypt=*/1,
                  /*sign=*/0,
                  /*user_auth=*/"", /*sensitive_data=*/"", /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.parent_name, primary.name);
}

TEST_F(AppTest, TestCreateFailsForECCSigningKey) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result =
      app->Create(primary.handle, TPM2_ALG_ECC, /*restricted=*/1, /*decrypt=*/1,
                  /*sign=*/0,
                  /*user_auth=*/"", /*sensitive_data=*/"", /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_TYPE, result.rc);
}

TEST_F(AppTest, TestCreateHASH) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult result = app->Create(primary.handle, TPM2_ALG_KEYEDHASH,
                                    /*restricted=*/0, /*decrypt=*/0,
                                    /*sign=*/0,
                                    /*user_auth=*/"",
                                    /*sensitive_data=*/"secret-data",
                                    /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.parent_name, primary.name);
}

TEST_F(AppTest, TestLoad) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult key = app->Create(primary.handle, TPM2_ALG_RSA, /*restricted=*/1,
                                 /*decrypt=*/1, /*sign=*/0,
                                 /*user_auth=*/"", /*sensitive_data=*/"",
                                 /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  LoadResult result =
      app->Load(primary.handle, key.tpm2b_private, key.tpm2b_public);
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
}

TEST_F(AppTest, TestRSASignVerify) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/0,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);
  SignResult result = app->Sign(primary.handle, TPM2_ALG_RSA, "Hello");
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(TPM2_ALG_RSASSA, result.sign_algo);
  EXPECT_EQ(TPM2_ALG_SHA256, result.hash_algo);
  EXPECT_GT(result.rsa_ssa_sig.size(), 0);
  EXPECT_EQ(result.ecdsa_r.size(), 0);
  EXPECT_EQ(result.ecdsa_s.size(), 0);
  EXPECT_EQ(TPM2_RC_SUCCESS,
            app->VerifySignature(primary.handle, "Hello", result));
  EXPECT_EQ(TPM2_RC_SIGNATURE + TPM2_RC_P + TPM2_RC_2,
            app->VerifySignature(primary.handle, "!ello", result));
}

TEST_F(AppTest, TestECCSignVerify) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/0,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);
  SignResult result = app->Sign(primary.handle, TPM2_ALG_ECC, "Hello");
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(TPM2_ALG_ECDSA, result.sign_algo);
  EXPECT_EQ(TPM2_ALG_SHA256, result.hash_algo);
  EXPECT_EQ(result.rsa_ssa_sig.size(), 0);
  EXPECT_GT(result.ecdsa_r.size(), 0);
  EXPECT_GT(result.ecdsa_s.size(), 0);
  EXPECT_EQ(TPM2_RC_SUCCESS,
            app->VerifySignature(primary.handle, "Hello", result));
  EXPECT_EQ(TPM2_RC_SIGNATURE + TPM2_RC_P + TPM2_RC_2,
            app->VerifySignature(primary.handle, "!ello", result));
}

TEST_F(AppTest, TestEncryptDecrypt) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_SYMCIPHER, /*restricted=*/0,
                         /*decrypt=*/1, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  const std::vector<uint8_t> kOriginal = {'H', 'e', 'l', 'l', 'o'};
  std::vector<uint8_t> encrypted = app->Encrypt(primary.handle, kOriginal);

  std::vector<uint8_t> message = app->Decrypt(primary.handle, encrypted);
  EXPECT_EQ(message, kOriginal);
}

TEST_F(AppTest, TestRSAEncryptDecrypt) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/0,
                         /*decrypt=*/1, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  const std::vector<uint8_t> kOriginal = {'H', 'e', 'l', 'l', 'o'};
  std::vector<uint8_t> encrypted = app->RSAEncrypt(primary.handle, kOriginal);

  std::vector<uint8_t> message = app->RSADecrypt(primary.handle, encrypted);
  EXPECT_EQ(message, kOriginal);
}

TEST_F(AppTest, TestEvictControl) {
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/0,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  SignResult sign_result = app->Sign(primary.handle, TPM2_ALG_ECC, "Hello");
  EXPECT_EQ(TPM2_RC_SUCCESS, sign_result.rc);

  TPM2_RC rc =
      app->EvictControl(TPM2_RH_OWNER, primary.handle, TPM2_PERSISTENT_FIRST);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  // Simulate restart.
  app->Shutdown();
  Simulator::PowerOff();
  Simulator::PowerOn();
  app->Startup();

  // Verify using persistent handle.
  EXPECT_EQ(TPM2_RC_SUCCESS,
            app->VerifySignature(TPM2_PERSISTENT_FIRST, "Hello", sign_result));
}

TEST_F(AppTest, TestNvReadWrite) {
  App *app = App::Get();
  const std::vector<uint8_t> kData = {1, 2, 3, 4};
  const uint32_t kNvIndex = 0x01c00002;
  EXPECT_EQ(TPM2_RC_SUCCESS, app->NvDefineSpace(kNvIndex, kData.size()));
  auto read_public_result = app->NvReadPublic(kNvIndex);
  EXPECT_EQ(TPM2_RC_SUCCESS, read_public_result.rc);
  EXPECT_EQ(kData.size(), read_public_result.data_size);
  EXPECT_EQ(TPM2_RC_SUCCESS, app->NvWrite(kNvIndex, kData));
  auto read_result = app->NvRead(kNvIndex, kData.size(), 0);
  EXPECT_EQ(TPM2_RC_SUCCESS, read_result.rc);
  EXPECT_EQ(read_result.data, kData);
}

TEST_F(AppTest, TestQuote) {
  App *app = App::Get();
  CreatePrimaryResult key =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  const std::string kNonce = "TestNonce";
  QuoteResult result = app->Quote(key.handle, kNonce);
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(TPM2_ALG_RSASSA, result.sign_algo);
  EXPECT_EQ(TPM2_ALG_SHA256, result.hash_algo);
  EXPECT_GT(result.rsa_ssa_sig.size(), 0);
  EXPECT_GT(result.tpm2b_attest.size(), 0);

  AttestInfo attest = Util::UnmarshalAttestBuffer(result.tpm2b_attest);
  EXPECT_EQ(TPM2_RC_SUCCESS, attest.rc);
  EXPECT_EQ(TPM2_GENERATED_VALUE, attest.magic);
  EXPECT_EQ(TPM2_ST_ATTEST_QUOTE, attest.type);
  EXPECT_EQ(attest.nonce, std::vector<uint8_t>(kNonce.begin(), kNonce.end()));
  EXPECT_GT(attest.selected_pcr_digest.size(), 0);
}

TEST_F(AppTest, TestHierarchyChangeAuth) {
  App *app = App::Get();
  const std::string kGoodAuth = "im-cool";
  const std::string kBadAuth = "im-fake";
  const std::string kEmptyAuth = "";

  EXPECT_EQ(TPM2_RC_SUCCESS,
            app->HierarchyChangeAuth(TPM2_RH_OWNER, kGoodAuth));

  app->SetAuthPassword(kBadAuth);

  CreatePrimaryResult key =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                         /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH, key.rc);

  app->SetAuthPassword(kGoodAuth);

  key = app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                           /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                           /*user_auth=*/"", /*sensitive_data=*/"",
                           /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  key = app->CreatePrimary(TPM2_RH_ENDORSEMENT, TPM2_ALG_ECC, /*restricted=*/1,
                           /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                           /*user_auth=*/"", /*sensitive_data=*/"",
                           /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_BAD_AUTH, key.rc);

  app->SetAuthPassword(kEmptyAuth);

  key = app->CreatePrimary(TPM2_RH_ENDORSEMENT, TPM2_ALG_ECC, /*restricted=*/1,
                           /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                           /*user_auth=*/"", /*sensitive_data=*/"",
                           /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  app->SetAuthPassword(kGoodAuth);
  EXPECT_EQ(TPM2_RC_SUCCESS,
            app->HierarchyChangeAuth(TPM2_RH_OWNER, kEmptyAuth));

  app->SetAuthPassword(kEmptyAuth);
  key = app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_ECC, /*restricted=*/1,
                           /*decrypt=*/0, /*sign=*/1, /*unique=*/"",
                           /*user_auth=*/"", /*sensitive_data=*/"",
                           /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);
}

TEST_F(AppTest, TestCreateWithUserAuth) {
  const std::string kGoodAuth = "secret_password";
  App *app = App::Get();
  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  CreateResult key = app->Create(primary.handle, TPM2_ALG_RSA, /*restricted=*/0,
                                 /*decrypt=*/1, /*sign=*/1,
                                 /*user_auth=*/kGoodAuth, /*sensitive_data=*/"",
                                 /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  LoadResult loaded =
      app->Load(primary.handle, key.tpm2b_private, key.tpm2b_public);
  EXPECT_EQ(TPM2_RC_SUCCESS, loaded.rc);

  const std::vector<uint8_t> kOriginal = {'H', 'e', 'l', 'l', 'o'};
  std::vector<uint8_t> encrypted = app->RSAEncrypt(loaded.handle, kOriginal);

  app->SetAuthPassword(kGoodAuth);
  std::vector<uint8_t> message = app->RSADecrypt(loaded.handle, encrypted);
  EXPECT_EQ(message, kOriginal);

  app->SetAuthPassword("");
}

TEST_F(AppTest, TestUnseal) {
  const std::string kGoodAuth = "secret_password";
  const std::string kBadAuth = "guess";
  const std::vector<uint8_t> kData = {'s', 'e', 'c', 'r', 'e', 't'};
  App *app = App::Get();
  CreatePrimaryResult key = app->CreatePrimary(
      TPM2_RH_OWNER, TPM2_ALG_KEYEDHASH, /*restricted=*/0,
      /*decrypt=*/0, /*sign=*/0, /*unique=*/"",
      /*user_auth=*/kGoodAuth,
      /*sensitive_data=*/std::string(kData.begin(), kData.end()),
      /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);
  app->SetAuthPassword(kBadAuth);
  UnsealResult result = app->Unseal(key.handle);
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_AUTH_FAIL, result.rc);

  app->SetAuthPassword(kGoodAuth);
  result = app->Unseal(key.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.sensitive_data, kData);

  app->SetAuthPassword("");
}

TEST_F(AppTest, TestPasswordSession) {
  App *app = App::Get();

  // Compute policy digest of trial session.
  StartAuthSessionResult trial = app->StartAuthSession(true);
  EXPECT_EQ(TPM2_RC_SUCCESS, trial.rc);

  const std::vector<uint8_t> kInitialPolicy(TPM2_SHA256_DIGEST_SIZE, 0);
  std::vector<uint8_t> policy_digest = app->PolicyGetDigest(trial.handle);
  EXPECT_EQ(policy_digest, kInitialPolicy);

  TPM2_RC rc = app->PolicyPassword(trial.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  policy_digest = app->PolicyGetDigest(trial.handle);
  EXPECT_NE(policy_digest, kInitialPolicy);

  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(trial.handle));

  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  // Seal data with auth policy.
  const std::string kGoodAuth = "secret_password";
  const std::string kBadAuth = "guess";
  const std::vector<uint8_t> kData = {'s', 'e', 'c', 'r', 'e', 't'};
  CreateResult key =
      app->Create(primary.handle, TPM2_ALG_KEYEDHASH, /*restricted=*/0,
                  /*decrypt=*/0, /*sign=*/0,
                  /*user_auth=*/kGoodAuth,
                  /*sensitive_data=*/std::string(kData.begin(), kData.end()),
                  /*auth_policy=*/policy_digest);
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  LoadResult loaded =
      app->Load(primary.handle, key.tpm2b_private, key.tpm2b_public);
  EXPECT_EQ(TPM2_RC_SUCCESS, loaded.rc);

  // Unseal without auth fails.
  UnsealResult result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_AUTH_UNAVAILABLE, result.rc);

  // Start auth session (trial = 0).
  StartAuthSessionResult session = app->StartAuthSession(false);
  EXPECT_EQ(TPM2_RC_SUCCESS, session.rc);

  // Use session to authenticate.
  app->SetSessionHandle(session.handle);

  result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_POLICY_FAIL, result.rc);

  rc = app->PolicyPassword(session.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  // Clear  DA lockout.
  app->SetSessionHandle(TPM2_RS_PW);
  rc = app->DictionaryAttackLockReset();
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  // This will fail with AUTH_FAIL (as opposed to POLICY_FAIL).
  app->SetSessionHandle(session.handle);
  result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_AUTH_FAIL, result.rc);

  app->SetAuthPassword(kGoodAuth);
  app->SetSessionHandle(session.handle);
  result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.sensitive_data, kData);

  app->SetSessionHandle(TPM2_RS_PW);
  app->SetAuthPassword("");
}

TEST_F(AppTest, TestPCRSession) {
  App *app = App::Get();

  // Compute policy digest of trial session.
  StartAuthSessionResult trial = app->StartAuthSession(true);
  EXPECT_EQ(TPM2_RC_SUCCESS, trial.rc);

  const std::vector<uint8_t> kInitialPolicy(TPM2_SHA256_DIGEST_SIZE, 0);
  std::vector<uint8_t> policy_digest = app->PolicyGetDigest(trial.handle);
  EXPECT_EQ(policy_digest, kInitialPolicy);

  // SHA56 of PCR0, PCR1, PCR2, PCR3 after PCR0 was extended with "Hello".
  const std::vector<uint8_t> kPcrDigest = {
      0xbb, 0x95, 0xd8, 0x81, 0x65, 0xcc, 0xf6, 0x86, 0x78, 0xbf, 0x1a,
      0x9a, 0xf3, 0x0d, 0x5d, 0xec, 0xe8, 0x1f, 0x41, 0xb4, 0x5c, 0x91,
      0x17, 0x4b, 0x23, 0x07, 0xf2, 0x6c, 0xa5, 0xd4, 0x10, 0xf2};

  // Require password and PCR values.
  TPM2_RC rc = app->PolicyPCR(trial.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  rc = app->PolicyPassword(trial.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  policy_digest = app->PolicyGetDigest(trial.handle);
  EXPECT_NE(policy_digest, kInitialPolicy);

  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(trial.handle));

  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  // Seal data with auth policy.
  const std::string kGoodAuth = "secret_password";
  const std::string kBadAuth = "guess";
  const std::vector<uint8_t> kData = {'s', 'e', 'c', 'r', 'e', 't'};
  CreateResult key =
      app->Create(primary.handle, TPM2_ALG_KEYEDHASH, /*restricted=*/0,
                  /*decrypt=*/0, /*sign=*/0,
                  /*user_auth=*/kGoodAuth,
                  /*sensitive_data=*/std::string(kData.begin(), kData.end()),
                  /*auth_policy=*/policy_digest);
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  LoadResult loaded =
      app->Load(primary.handle, key.tpm2b_private, key.tpm2b_public);
  EXPECT_EQ(TPM2_RC_SUCCESS, loaded.rc);

  // Start auth session (trial = 0).
  StartAuthSessionResult session = app->StartAuthSession(false);
  EXPECT_EQ(TPM2_RC_SUCCESS, session.rc);

  // Use session to authenticate.
  app->SetSessionHandle(session.handle);

  UnsealResult result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_POLICY_FAIL, result.rc);

  // Fails because the PCR values don't match.
  rc = app->PolicyPCR(session.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_P + TPM2_RC_1 + TPM2_RC_VALUE, rc);

  app->SetSessionHandle(TPM2_RS_PW);
  rc = app->ExtendPcr(0, "Hello");
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  // Now it passes.
  app->SetSessionHandle(session.handle);
  rc = app->PolicyPCR(session.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  rc = app->PolicyPassword(session.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_1 + TPM2_RC_S + TPM2_RC_AUTH_FAIL, result.rc);

  app->SetAuthPassword(kGoodAuth);
  app->SetSessionHandle(session.handle);
  result = app->Unseal(loaded.handle);
  EXPECT_EQ(TPM2_RC_SUCCESS, result.rc);
  EXPECT_EQ(result.sensitive_data, kData);

  app->SetSessionHandle(TPM2_RS_PW);
  app->SetAuthPassword("");
}

TEST_F(AppTest, TestSealedKey) {
  App *app = App::Get();

  // Compute policy digest of trial session.
  StartAuthSessionResult trial = app->StartAuthSession(true);
  EXPECT_EQ(TPM2_RC_SUCCESS, trial.rc);

  // SHA56 of PCR0, PCR1, PCR2, PCR3 after PCR0 was extended with "Hello".
  const std::vector<uint8_t> kPcrDigest = {
      0xbb, 0x95, 0xd8, 0x81, 0x65, 0xcc, 0xf6, 0x86, 0x78, 0xbf, 0x1a,
      0x9a, 0xf3, 0x0d, 0x5d, 0xec, 0xe8, 0x1f, 0x41, 0xb4, 0x5c, 0x91,
      0x17, 0x4b, 0x23, 0x07, 0xf2, 0x6c, 0xa5, 0xd4, 0x10, 0xf2};

  // Require password and PCR values.
  TPM2_RC rc = app->PolicyPCR(trial.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  std::vector<uint8_t> policy_digest = app->PolicyGetDigest(trial.handle);

  EXPECT_EQ(TPM2_RC_SUCCESS, app->FlushContext(trial.handle));

  CreatePrimaryResult primary =
      app->CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA, /*restricted=*/1,
                         /*decrypt=*/1, /*sign=*/0, /*unique=*/"",
                         /*user_auth=*/"", /*sensitive_data=*/"",
                         /*auth_policy=*/{});
  EXPECT_EQ(TPM2_RC_SUCCESS, primary.rc);

  // Seal key with auth policy.
  CreateResult key =
      app->Create(primary.handle, TPM2_ALG_SYMCIPHER, /*restricted=*/0,
                  /*decrypt=*/1, /*sign=*/1,
                  /*user_auth=*/"",
                  /*sensitive_data=*/"",
                  /*auth_policy=*/policy_digest);
  EXPECT_EQ(TPM2_RC_SUCCESS, key.rc);

  LoadResult loaded =
      app->Load(primary.handle, key.tpm2b_private, key.tpm2b_public);
  EXPECT_EQ(TPM2_RC_SUCCESS, loaded.rc);

  rc = app->ExtendPcr(0, "Hello");
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  // Start auth session (trial = 0).
  StartAuthSessionResult session = app->StartAuthSession(false);
  EXPECT_EQ(TPM2_RC_SUCCESS, session.rc);

  // Use session to authenticate.
  app->SetSessionHandle(session.handle);
  rc = app->PolicyPCR(session.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  const std::vector<uint8_t> kOriginal = {'H', 'e', 'l', 'l', 'o'};
  std::vector<uint8_t> encrypted = app->Encrypt(loaded.handle, kOriginal);

  // Session policy digest is reset after each command.
  rc = app->PolicyPCR(session.handle, kPcrDigest);
  EXPECT_EQ(TPM2_RC_SUCCESS, rc);

  std::vector<uint8_t> message = app->Decrypt(loaded.handle, encrypted);
  EXPECT_EQ(message, kOriginal);

  app->SetSessionHandle(TPM2_RS_PW);
}

} // namespace
} // namespace tpm_js
