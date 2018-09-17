/********************************************************************************/
/*										*/
/*			  Command Header Includes   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Commands.h 1047 2017-07-20 18:27:34Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016, 2017				*/
/*										*/
/********************************************************************************/

#ifndef COMMANDS_H
#define COMMANDS_H

#ifdef TPM_CC_Startup
#include "Startup_fp.h"
#endif
#ifdef TPM_CC_Shutdown
#include "Shutdown_fp.h"
#endif
/* Testing */
#ifdef TPM_CC_SelfTest
#include "SelfTest_fp.h"
#endif
#ifdef TPM_CC_IncrementalSelfTest
#include "IncrementalSelfTest_fp.h"
#endif
#ifdef TPM_CC_GetTestResult
#include "GetTestResult_fp.h"
#endif
/* Session Commands */
#ifdef TPM_CC_StartAuthSession
#include "StartAuthSession_fp.h"
#endif
#ifdef TPM_CC_PolicyRestart
#include "PolicyRestart_fp.h"
#endif
/* Object Commands */
#ifdef TPM_CC_Create
#include "Create_fp.h"
#endif
#ifdef TPM_CC_Load
#include "Load_fp.h"
#endif
#ifdef TPM_CC_LoadExternal
#include "LoadExternal_fp.h"
#endif
#ifdef TPM_CC_ReadPublic
#include "ReadPublic_fp.h"
#endif
#ifdef TPM_CC_ActivateCredential
#include "ActivateCredential_fp.h"
#endif
#ifdef TPM_CC_MakeCredential
#include "MakeCredential_fp.h"
#endif
#ifdef TPM_CC_Unseal
#include "Unseal_fp.h"
#endif
#ifdef TPM_CC_ObjectChangeAuth
#include "ObjectChangeAuth_fp.h"
#endif
#ifdef TPM_CC_CreateLoaded
#include "CreateLoaded_fp.h"
#endif
/* Duplication Commands */
#ifdef TPM_CC_Duplicate
#include "Duplicate_fp.h"
#endif
#ifdef TPM_CC_Rewrap
#include "Rewrap_fp.h"
#endif
#ifdef TPM_CC_Import
#include "Import_fp.h"
#endif
/* Asymmetric Primitives */
#ifdef TPM_CC_RSA_Encrypt
#include "RSA_Encrypt_fp.h"
#endif
#ifdef TPM_CC_RSA_Decrypt
#include "RSA_Decrypt_fp.h"
#endif
#ifdef TPM_CC_ECDH_KeyGen
#include "ECDH_KeyGen_fp.h"
#endif
#ifdef TPM_CC_ECDH_ZGen
#include "ECDH_ZGen_fp.h"
#endif
#ifdef TPM_CC_ECC_Parameters
#include "ECC_Parameters_fp.h"
#endif
#ifdef TPM_CC_ZGen_2Phase
#include "ZGen_2Phase_fp.h"
#endif
/* Symmetric Primitives */
#ifdef TPM_CC_EncryptDecrypt
#include "EncryptDecrypt_fp.h"
#endif
#ifdef TPM_CC_EncryptDecrypt2
#include "EncryptDecrypt2_fp.h"
#endif
#ifdef TPM_CC_Hash
#include "Hash_fp.h"
#endif
#ifdef TPM_CC_HMAC
#include "HMAC_fp.h"
#endif
#ifdef TPM_CC_MAC
#include "MAC_fp.h"
#endif
/* Random Number Generator */
#ifdef TPM_CC_GetRandom
#include "GetRandom_fp.h"
#endif
#ifdef TPM_CC_StirRandom
#include "StirRandom_fp.h"
#endif
/* Hash/HMAC/Event Sequences */
#ifdef TPM_CC_HMAC_Start
#include "HMAC_Start_fp.h"
#endif
#ifdef TPM_CC_MAC_Start
#include "MAC_Start_fp.h"
#endif
#ifdef TPM_CC_HashSequenceStart
#include "HashSequenceStart_fp.h"
#endif
#ifdef TPM_CC_SequenceUpdate
#include "SequenceUpdate_fp.h"
#endif
#ifdef TPM_CC_SequenceComplete
#include "SequenceComplete_fp.h"
#endif
#ifdef TPM_CC_EventSequenceComplete
#include "EventSequenceComplete_fp.h"
#endif
/* Attestation Commands */
#ifdef TPM_CC_Certify
#include "Certify_fp.h"
#endif
#ifdef TPM_CC_CertifyCreation
#include "CertifyCreation_fp.h"
#endif
#ifdef TPM_CC_Quote
#include "Quote_fp.h"
#endif
#ifdef TPM_CC_GetSessionAuditDigest
#include "GetSessionAuditDigest_fp.h"
#endif
#ifdef TPM_CC_GetCommandAuditDigest
#include "GetCommandAuditDigest_fp.h"
#endif
#ifdef TPM_CC_GetTime
#include "GetTime_fp.h"
#endif
/* Ephemeral EC Keys */
#ifdef TPM_CC_Commit
#include "Commit_fp.h"
#endif
#ifdef TPM_CC_EC_Ephemeral
#include "EC_Ephemeral_fp.h"
#endif
/* Signing and Signature Verification */
#ifdef TPM_CC_VerifySignature
#include "VerifySignature_fp.h"
#endif
#ifdef TPM_CC_Sign
#include "Sign_fp.h"
#endif
/* Command Audit */
#ifdef TPM_CC_SetCommandCodeAuditStatus
#include "SetCommandCodeAuditStatus_fp.h"
#endif
/* Integrity Collection (PCR) */
#ifdef TPM_CC_PCR_Extend
#include "PCR_Extend_fp.h"
#endif
#ifdef TPM_CC_PCR_Event
#include "PCR_Event_fp.h"
#endif
#ifdef TPM_CC_PCR_Read
#include "PCR_Read_fp.h"
#endif
#ifdef TPM_CC_PCR_Allocate
#include "PCR_Allocate_fp.h"
#endif
#ifdef TPM_CC_PCR_SetAuthPolicy
#include "PCR_SetAuthPolicy_fp.h"
#endif
#ifdef TPM_CC_PCR_SetAuthValue
#include "PCR_SetAuthValue_fp.h"
#endif
#ifdef TPM_CC_PCR_Reset
#include "PCR_Reset_fp.h"
#endif
/* Enhanced Authorization (EA) Commands */
#ifdef TPM_CC_PolicySigned
#include "PolicySigned_fp.h"
#endif
#ifdef TPM_CC_PolicySecret
#include "PolicySecret_fp.h"
#endif
#ifdef TPM_CC_PolicyTicket
#include "PolicyTicket_fp.h"
#endif
#ifdef TPM_CC_PolicyOR
#include "PolicyOR_fp.h"
#endif
#ifdef TPM_CC_PolicyPCR
#include "PolicyPCR_fp.h"
#endif
#ifdef TPM_CC_PolicyLocality
#include "PolicyLocality_fp.h"
#endif
#ifdef TPM_CC_PolicyNV
#include "PolicyNV_fp.h"
#endif
#ifdef TPM_CC_PolicyCounterTimer
#include "PolicyCounterTimer_fp.h"
#endif
#ifdef TPM_CC_PolicyCommandCode
#include "PolicyCommandCode_fp.h"
#endif
#ifdef TPM_CC_PolicyPhysicalPresence
#include "PolicyPhysicalPresence_fp.h"
#endif
#ifdef TPM_CC_PolicyCpHash
#include "PolicyCpHash_fp.h"
#endif
#ifdef TPM_CC_PolicyNameHash
#include "PolicyNameHash_fp.h"
#endif
#ifdef TPM_CC_PolicyDuplicationSelect
#include "PolicyDuplicationSelect_fp.h"
#endif
#ifdef TPM_CC_PolicyAuthorize
#include "PolicyAuthorize_fp.h"
#endif
#ifdef TPM_CC_PolicyAuthValue
#include "PolicyAuthValue_fp.h"
#endif
#ifdef TPM_CC_PolicyPassword
#include "PolicyPassword_fp.h"
#endif
#ifdef TPM_CC_PolicyGetDigest
#include "PolicyGetDigest_fp.h"
#endif
#ifdef TPM_CC_PolicyNvWritten
#include "PolicyNvWritten_fp.h"
#endif
#ifdef TPM_CC_PolicyTemplate
#include "PolicyTemplate_fp.h"
#endif
#ifdef TPM_CC_PolicyAuthorizeNV
#include "PolicyAuthorizeNV_fp.h"
#endif
/* Hierarchy Commands */
#ifdef TPM_CC_CreatePrimary
#include "CreatePrimary_fp.h"
#endif
#ifdef TPM_CC_HierarchyControl
#include "HierarchyControl_fp.h"
#endif
#ifdef TPM_CC_SetPrimaryPolicy
#include "SetPrimaryPolicy_fp.h"
#endif
#ifdef TPM_CC_ChangePPS
#include "ChangePPS_fp.h"
#endif
#ifdef TPM_CC_ChangeEPS
#include "ChangeEPS_fp.h"
#endif
#ifdef TPM_CC_Clear
#include "Clear_fp.h"
#endif
#ifdef TPM_CC_ClearControl
#include "ClearControl_fp.h"
#endif
#ifdef TPM_CC_HierarchyChangeAuth
#include "HierarchyChangeAuth_fp.h"
#endif
/* Dictionary Attack Functions */
#ifdef TPM_CC_DictionaryAttackLockReset
#include "DictionaryAttackLockReset_fp.h"
#endif
#ifdef TPM_CC_DictionaryAttackParameters
#include "DictionaryAttackParameters_fp.h"
#endif
/* Miscellaneous Management Functions */
#ifdef TPM_CC_PP_Commands
#include "PP_Commands_fp.h"
#endif
#ifdef TPM_CC_SetAlgorithmSet
#include "SetAlgorithmSet_fp.h"
#endif
/* Field Upgrade */
#ifdef TPM_CC_FieldUpgradeStart
#include "FieldUpgradeStart_fp.h"
#endif
#ifdef TPM_CC_FieldUpgradeData
#include "FieldUpgradeData_fp.h"
#endif
#ifdef TPM_CC_FirmwareRead
#include "FirmwareRead_fp.h"
#endif
/* Context Management */
#ifdef TPM_CC_ContextSave
#include "ContextSave_fp.h"
#endif
#ifdef TPM_CC_ContextLoad
#include "ContextLoad_fp.h"
#endif
#ifdef TPM_CC_FlushContext
#include "FlushContext_fp.h"
#endif
#ifdef TPM_CC_EvictControl
#include "EvictControl_fp.h"
#endif
/* Clocks and Timers */
#ifdef TPM_CC_ReadClock
#include "ReadClock_fp.h"
#endif
#ifdef TPM_CC_ClockSet
#include "ClockSet_fp.h"
#endif
#ifdef TPM_CC_ClockRateAdjust
#include "ClockRateAdjust_fp.h"
#endif
/* Capability Commands */
#ifdef TPM_CC_GetCapability
#include "GetCapability_fp.h"
#endif
#ifdef TPM_CC_TestParms
#include "TestParms_fp.h"
#endif
#ifdef TPM_CC_NV_DefineSpace
#include "NV_DefineSpace_fp.h"
#endif
#ifdef TPM_CC_NV_UndefineSpace
#include "NV_UndefineSpace_fp.h"
#endif
#ifdef TPM_CC_NV_UndefineSpaceSpecial
#include "NV_UndefineSpaceSpecial_fp.h"
#endif
#ifdef TPM_CC_NV_ReadPublic
#include "NV_ReadPublic_fp.h"
#endif
#ifdef TPM_CC_NV_Write
#include "NV_Write_fp.h"
#endif
#ifdef TPM_CC_NV_Increment
#include "NV_Increment_fp.h"
#endif
#ifdef TPM_CC_NV_Extend
#include "NV_Extend_fp.h"
#endif
#ifdef TPM_CC_NV_SetBits
#include "NV_SetBits_fp.h"
#endif
#ifdef TPM_CC_NV_WriteLock
#include "NV_WriteLock_fp.h"
#endif
#ifdef TPM_CC_NV_GlobalWriteLock
#include "NV_GlobalWriteLock_fp.h"
#endif
#ifdef TPM_CC_NV_Read
#include "NV_Read_fp.h"
#endif
#ifdef TPM_CC_NV_ReadLock
#include "NV_ReadLock_fp.h"
#endif
#ifdef TPM_CC_NV_ChangeAuth
#include "NV_ChangeAuth_fp.h"
#endif
#ifdef TPM_CC_NV_Certify
#include "NV_Certify_fp.h"
#endif

/* Attached Components */

#ifdef TPM_CC_AC_GetCapability
#include "AC_GetCapability_fp.h"
#endif
#ifdef TPM_CC_AC_Send
#include "AC_Send_fp.h"
#endif
#ifdef TPM_CC_Policy_AC_SendSelect
#include "Policy_AC_SendSelect_fp.h"
#endif

/* Vendor Specific */
#ifdef TPM_CC_Vendor_TCG_Test
#include "Vendor_TCG_Test_fp.h"
#endif

/* Nuvoton Commands */
#ifdef TPM_NUVOTON
#include "ntc2_fp.h"
#endif

#endif
