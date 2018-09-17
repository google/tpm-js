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

#include "tss_adapter.h"

#include <gtest/gtest.h>

namespace tpm_js {
namespace {

TEST(TssAdapterTest, ContextIsNotNull) {
  TssAdapter::RunCommand cb = [](const std::vector<uint8_t>& cmd) {
    return std::vector<uint8_t>{};
  };
  TssAdapter tss(cb);
  EXPECT_NE(tss.GetSysContext(), nullptr);
}

TEST(TssAdapterTest, ExecutesCommandWithSimulator) {
  const std::vector<uint8_t> kClear = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
                                       0x00, 0x00, 0x01, 0x44, 0x00, 0x00};
  const std::vector<uint8_t> kSuccess = {0x80, 0x01, 0x00, 0x00, 0x00,
                                         0x0A, 0x00, 0x00, 0x00, 0x00};
  TssAdapter::RunCommand cb = [&kClear,
                               &kSuccess](const std::vector<uint8_t>& cmd) {
    EXPECT_EQ(cmd, kClear);
    return kSuccess;
  };
  TssAdapter tss(cb);
  TPM2_RC rc = Tss2_Sys_Startup(tss.GetSysContext(), TPM2_SU_CLEAR);
  EXPECT_EQ(rc, TPM2_RC_SUCCESS);
}

}  // namespace
}  // namespace tpm_js
