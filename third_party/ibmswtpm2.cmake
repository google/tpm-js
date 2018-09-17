# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
if(NOT IBMSWTPM2_ROOT_DIR)
  set(IBMSWTPM2_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ibmswtpm2/src)
endif()

set (
  IBMSWTPM2_SOURCES

  ${IBMSWTPM2_ROOT_DIR}/AlgorithmCap.c
  ${IBMSWTPM2_ROOT_DIR}/AlgorithmTests.c
  ${IBMSWTPM2_ROOT_DIR}/AsymmetricCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Attest_spt.c
  ${IBMSWTPM2_ROOT_DIR}/AttestationCommands.c
  ${IBMSWTPM2_ROOT_DIR}/AuditCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Bits.c
  ${IBMSWTPM2_ROOT_DIR}/BnConvert.c
  ${IBMSWTPM2_ROOT_DIR}/BnEccData.c
  ${IBMSWTPM2_ROOT_DIR}/BnMath.c
  ${IBMSWTPM2_ROOT_DIR}/BnMemory.c
  ${IBMSWTPM2_ROOT_DIR}/Cancel.c
  ${IBMSWTPM2_ROOT_DIR}/CapabilityCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Clock.c
  ${IBMSWTPM2_ROOT_DIR}/ClockCommands.c
  ${IBMSWTPM2_ROOT_DIR}/CommandAudit.c
  ${IBMSWTPM2_ROOT_DIR}/CommandCodeAttributes.c
  ${IBMSWTPM2_ROOT_DIR}/CommandDispatcher.c
  ${IBMSWTPM2_ROOT_DIR}/ContextCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Context_spt.c
  ${IBMSWTPM2_ROOT_DIR}/CryptDes.c
  ${IBMSWTPM2_ROOT_DIR}/CryptEccKeyExchange.c
  ${IBMSWTPM2_ROOT_DIR}/CryptEccMain.c
  ${IBMSWTPM2_ROOT_DIR}/CryptEccSignature.c
  ${IBMSWTPM2_ROOT_DIR}/CryptHash.c
  ${IBMSWTPM2_ROOT_DIR}/CryptHashData.c
  ${IBMSWTPM2_ROOT_DIR}/CryptPrime.c
  ${IBMSWTPM2_ROOT_DIR}/CryptPrimeSieve.c
  ${IBMSWTPM2_ROOT_DIR}/CryptRand.c
  ${IBMSWTPM2_ROOT_DIR}/CryptRsa.c
  ${IBMSWTPM2_ROOT_DIR}/CryptSelfTest.c
  ${IBMSWTPM2_ROOT_DIR}/CryptSym.c
  ${IBMSWTPM2_ROOT_DIR}/CryptUtil.c
  ${IBMSWTPM2_ROOT_DIR}/DA.c
  ${IBMSWTPM2_ROOT_DIR}/DictionaryCommands.c
  ${IBMSWTPM2_ROOT_DIR}/DuplicationCommands.c
  ${IBMSWTPM2_ROOT_DIR}/EACommands.c
  ${IBMSWTPM2_ROOT_DIR}/EncryptDecrypt_spt.c
  ${IBMSWTPM2_ROOT_DIR}/Entity.c
  ${IBMSWTPM2_ROOT_DIR}/Entropy.c
  ${IBMSWTPM2_ROOT_DIR}/EphemeralCommands.c
  ${IBMSWTPM2_ROOT_DIR}/ExecCommand.c
  ${IBMSWTPM2_ROOT_DIR}/Global.c
  ${IBMSWTPM2_ROOT_DIR}/Handle.c
  ${IBMSWTPM2_ROOT_DIR}/HashCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Hierarchy.c
  ${IBMSWTPM2_ROOT_DIR}/HierarchyCommands.c
  ${IBMSWTPM2_ROOT_DIR}/IoBuffers.c
  ${IBMSWTPM2_ROOT_DIR}/IntegrityCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Locality.c
  ${IBMSWTPM2_ROOT_DIR}/LocalityPlat.c
  ${IBMSWTPM2_ROOT_DIR}/ManagementCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Manufacture.c
  ${IBMSWTPM2_ROOT_DIR}/Marshal.c
  ${IBMSWTPM2_ROOT_DIR}/MathOnByteBuffers.c
  ${IBMSWTPM2_ROOT_DIR}/Memory.c
  ${IBMSWTPM2_ROOT_DIR}/NVCommands.c
  ${IBMSWTPM2_ROOT_DIR}/NVDynamic.c
  ${IBMSWTPM2_ROOT_DIR}/NVMem.c
  ${IBMSWTPM2_ROOT_DIR}/NVReserved.c
  ${IBMSWTPM2_ROOT_DIR}/NV_spt.c
  ${IBMSWTPM2_ROOT_DIR}/Object.c
  ${IBMSWTPM2_ROOT_DIR}/ObjectCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Object_spt.c
  ${IBMSWTPM2_ROOT_DIR}/PCR.c
  ${IBMSWTPM2_ROOT_DIR}/PP.c
  ${IBMSWTPM2_ROOT_DIR}/PPPlat.c
  ${IBMSWTPM2_ROOT_DIR}/PlatformData.c
  ${IBMSWTPM2_ROOT_DIR}/Policy_spt.c
  ${IBMSWTPM2_ROOT_DIR}/Power.c
  ${IBMSWTPM2_ROOT_DIR}/PowerPlat.c
  ${IBMSWTPM2_ROOT_DIR}/PrimeData.c
  ${IBMSWTPM2_ROOT_DIR}/PropertyCap.c
  ${IBMSWTPM2_ROOT_DIR}/RandomCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Response.c
  ${IBMSWTPM2_ROOT_DIR}/ResponseCodeProcessing.c
  ${IBMSWTPM2_ROOT_DIR}/RsaKeyCache.c
  ${IBMSWTPM2_ROOT_DIR}/RunCommand.c
  ${IBMSWTPM2_ROOT_DIR}/Session.c
  ${IBMSWTPM2_ROOT_DIR}/SessionCommands.c
  ${IBMSWTPM2_ROOT_DIR}/SessionProcess.c
  ${IBMSWTPM2_ROOT_DIR}/SigningCommands.c
  ${IBMSWTPM2_ROOT_DIR}/StartupCommands.c
  ${IBMSWTPM2_ROOT_DIR}/SymmetricCommands.c
  ${IBMSWTPM2_ROOT_DIR}/TPMCmdp.c
  ${IBMSWTPM2_ROOT_DIR}/TestingCommands.c
  ${IBMSWTPM2_ROOT_DIR}/Ticket.c
  ${IBMSWTPM2_ROOT_DIR}/Time.c
  ${IBMSWTPM2_ROOT_DIR}/TpmFail.c
  ${IBMSWTPM2_ROOT_DIR}/TpmSizeChecks.c
  ${IBMSWTPM2_ROOT_DIR}/TpmToOsslDesSupport.c
  ${IBMSWTPM2_ROOT_DIR}/TpmToOsslMath.c
  ${IBMSWTPM2_ROOT_DIR}/TpmToOsslSupport.c
  ${IBMSWTPM2_ROOT_DIR}/Unique.c
  ${IBMSWTPM2_ROOT_DIR}/Unmarshal.c
  ${IBMSWTPM2_ROOT_DIR}/Vendor_TCG_Test.c
  ${IBMSWTPM2_ROOT_DIR}/ntc2lib.c
  ${IBMSWTPM2_ROOT_DIR}/ntc2.c
)

