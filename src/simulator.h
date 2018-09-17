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

namespace tpm_js {

// Low level access to the software TPM simulator (third_party/ibmswtpm2).
class Simulator {
public:
  static void PowerOn();
  static void PowerOff();
  static void ManufactureReset();

  static int IsPoweredOn();
  static int IsStarted();
  static int IsManufactured();
  static std::vector<uint8_t> GetPcr(int n);
  static std::vector<uint8_t> GetEndorsementSeed();
  static std::vector<uint8_t> GetPlatformSeed();
  static std::vector<uint8_t> GetOwnerSeed();
  static std::vector<uint8_t> GetNullSeed();
  static int GetBootCounter();

  static std::vector<uint8_t>
  ExecuteCommand(const std::vector<uint8_t> &command);

private:
  // static only
  ~Simulator();
};

} // namespace tpm_js
