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

#include "simulator.h"

#include <gtest/gtest.h>

namespace tpm_js {
namespace {

TEST(SimulatorTest, TestPowerOnOff) {
  EXPECT_EQ(Simulator::IsPoweredOn(), false);
  Simulator::PowerOn();
  EXPECT_EQ(Simulator::IsPoweredOn(), true);
  Simulator::PowerOff();
  EXPECT_EQ(Simulator::IsPoweredOn(), false);
}

TEST(SimulatorTest, TestManufactureResetGeneratesNewSeeds) {
  EXPECT_EQ(Simulator::IsManufactured(), false);
  Simulator::PowerOn();
  Simulator::ManufactureReset();
  EXPECT_EQ(Simulator::IsManufactured(), true);
  auto eseed_before = Simulator::GetEndorsementSeed();
  Simulator::ManufactureReset();
  auto eseed_after = Simulator::GetEndorsementSeed();
  EXPECT_NE(eseed_before, eseed_after);
}

} // namespace
} // namespace tpm_js
