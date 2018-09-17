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

const TPM2_ALG_ERROR = 0x0000;
const TPM2_ALG_RSA = 0x0001;
const TPM2_ALG_SHA = 0x0004;
const TPM2_ALG_SHA1 = 0x0004;
const TPM2_ALG_HMAC = 0x0005;
const TPM2_ALG_AES = 0x0006;
const TPM2_ALG_MGF1 = 0x0007;
const TPM2_ALG_KEYEDHASH = 0x0008;
const TPM2_ALG_XOR = 0x000A;
const TPM2_ALG_SHA256 = 0x000B;
const TPM2_ALG_SHA384 = 0x000C;
const TPM2_ALG_SHA512 = 0x000D;
const TPM2_ALG_NULL = 0x0010;
const TPM2_ALG_SM3_256 = 0x0012;
const TPM2_ALG_SM4 = 0x0013;
const TPM2_ALG_RSASSA = 0x0014;
const TPM2_ALG_RSAES = 0x0015;
const TPM2_ALG_RSAPSS = 0x0016;
const TPM2_ALG_OAEP = 0x0017;
const TPM2_ALG_ECDSA = 0x0018;
const TPM2_ALG_ECDH = 0x0019;
const TPM2_ALG_ECDAA = 0x001A;
const TPM2_ALG_SM2 = 0x001B;
const TPM2_ALG_ECSCHNORR = 0x001C;
const TPM2_ALG_ECMQV = 0x001D;
const TPM2_ALG_KDF1_SP800_56A = 0x0020;
const TPM2_ALG_KDF2 = 0x0021;
const TPM2_ALG_KDF1_SP800_108 = 0x0022;
const TPM2_ALG_ECC = 0x0023;
const TPM2_ALG_SYMCIPHER = 0x0025;
const TPM2_ALG_CAMELLIA = 0x0026;
const TPM2_ALG_CTR = 0x0040;
const TPM2_ALG_SHA3_256 = 0x0027;
const TPM2_ALG_SHA3_384 = 0x0028;
const TPM2_ALG_SHA3_512 = 0x0029;
const TPM2_ALG_OFB = 0x0041;
const TPM2_ALG_CBC = 0x0042;
const TPM2_ALG_CFB = 0x0043;
const TPM2_ALG_ECB = 0x0044;


const TPM2_RC_SUCCESS = (0x000);
const TPM2_RC_BAD_TAG = (0x01E); /* defined for compatibility with TPM 1.2 */
const TPM2_RC_VER1 = (0x100); /* set for all format 0 response codes */
const TPM2_RC_INITIALIZE = (TPM2_RC_VER1 + 0x000); /* TPM not initialized by TPM2_Startup or already initialized */
const TPM2_RC_FAILURE = (TPM2_RC_VER1 + 0x001); /* commands not being accepted because of a TPM failure. NOTE This may be returned by TPM2_GetTestResult as the testResult parameter. */
const TPM2_RC_SEQUENCE = (TPM2_RC_VER1 + 0x003); /* improper use of a sequence handle */
const TPM2_RC_PRIVATE = (TPM2_RC_VER1 + 0x00B); /* not currently used */
const TPM2_RC_HMAC = (TPM2_RC_VER1 + 0x019); /* not currently used */
const TPM2_RC_DISABLED = (TPM2_RC_VER1 + 0x020); /* the command is disabled */
const TPM2_RC_EXCLUSIVE = (TPM2_RC_VER1 + 0x021); /* command failed because audit sequence required exclusivity */
const TPM2_RC_AUTH_TYPE = (TPM2_RC_VER1 + 0x024); /* authorization handle is not correct for command */
const TPM2_RC_AUTH_MISSING = (TPM2_RC_VER1 + 0x025); /* command requires an authorization session for handle and it is not present. */
const TPM2_RC_POLICY = (TPM2_RC_VER1 + 0x026); /* policy failure in math operation or an invalid authPolicy value */
const TPM2_RC_PCR = (TPM2_RC_VER1 + 0x027); /* PCR check fail */
const TPM2_RC_PCR_CHANGED = (TPM2_RC_VER1 + 0x028); /* PCR have changed since checked. */
const TPM2_RC_UPGRADE = (TPM2_RC_VER1 + 0x02D); /* For all commands, other than TPM2_FieldUpgradeData, this code indicates that the TPM is in field upgrade mode. For TPM2_FieldUpgradeData, this code indicates that the TPM is not in field upgrade mode */
const TPM2_RC_TOO_MANY_CONTEXTS = (TPM2_RC_VER1 + 0x02E); /* context ID counter is at maximum. */
const TPM2_RC_AUTH_UNAVAILABLE = (TPM2_RC_VER1 + 0x02F); /* authValue or authPolicy is not available for selected entity. */
const TPM2_RC_REBOOT = (TPM2_RC_VER1 + 0x030); /* a _TPM_Init and StartupCLEAR is required before the TPM can resume operation. */
const TPM2_RC_UNBALANCED = (TPM2_RC_VER1 + 0x031); /* the protection algorithms hash and symmetric are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm. */
const TPM2_RC_COMMAND_SIZE = (TPM2_RC_VER1 + 0x042); /* command commandSize value is inconsistent with contents of the command buffer. Either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header */
const TPM2_RC_COMMAND_CODE = (TPM2_RC_VER1 + 0x043); /* command code not supported */
const TPM2_RC_AUTHSIZE = (TPM2_RC_VER1 + 0x044); /* the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required */
const TPM2_RC_AUTH_CONTEXT = (TPM2_RC_VER1 + 0x045); /* use of an authorization session with a context command or another command that cannot have an authorization session. */
const TPM2_RC_NV_RANGE = (TPM2_RC_VER1 + 0x046); /* NV offset+size is out of range. */
const TPM2_RC_NV_SIZE = (TPM2_RC_VER1 + 0x047); /* Requested allocation size is larger than allowed. */
const TPM2_RC_NV_LOCKED = (TPM2_RC_VER1 + 0x048); /* NV access locked. */
const TPM2_RC_NV_AUTHORIZATION = (TPM2_RC_VER1 + 0x049); /* NV access authorization fails in command actions this failure does not affect lockout.action */
const TPM2_RC_NV_UNINITIALIZED = (TPM2_RC_VER1 + 0x04A); /* an NV Index is used before being initialized or the state saved by TPM2_ShutdownSTATE could not be restored */
const TPM2_RC_NV_SPACE = (TPM2_RC_VER1 + 0x04B); /* insufficient space for NV allocation */
const TPM2_RC_NV_DEFINED = (TPM2_RC_VER1 + 0x04C); /* NV Index or persistent object already defined */
const TPM2_RC_BAD_CONTEXT = (TPM2_RC_VER1 + 0x050); /* context in TPM2_ContextLoad is not valid */
const TPM2_RC_CPHASH = (TPM2_RC_VER1 + 0x051); /* cpHash value already set or not correct for use */
const TPM2_RC_PARENT = (TPM2_RC_VER1 + 0x052); /* handle for parent is not a valid parent */
const TPM2_RC_NEEDS_TEST = (TPM2_RC_VER1 + 0x053); /* some function needs testing. */
const TPM2_RC_NO_RESULT = (TPM2_RC_VER1 + 0x054); /* returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code. */
const TPM2_RC_SENSITIVE = (TPM2_RC_VER1 + 0x055); /* the sensitive area did not unmarshal correctly after decryption. This code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred */
const TPM2_RC_MAX_FM0 = (TPM2_RC_VER1 + 0x07F); /* largest version 1 code that is not a warning */
const TPM2_RC_FMT1 = (0x080); /* This bit is SET in all format 1 response codes. The codes in this group may have a value added to them to indicate the handle session or parameter to which they apply. */
const TPM2_RC_ASYMMETRIC = (TPM2_RC_FMT1 + 0x001); /* asymmetric algorithm not supported or not correct */
const TPM2_RC_ATTRIBUTES = (TPM2_RC_FMT1 + 0x002); /* inconsistent attributes */
const TPM2_RC_HASH = (TPM2_RC_FMT1 + 0x003); /* hash algorithm not supported or not appropriate */
const TPM2_RC_VALUE = (TPM2_RC_FMT1 + 0x004); /* value is out of range or is not correct for the context */
const TPM2_RC_HIERARCHY = (TPM2_RC_FMT1 + 0x005); /* hierarchy is not enabled or is not correct for the use */
const TPM2_RC_KEY_SIZE = (TPM2_RC_FMT1 + 0x007); /* key size is not supported */
const TPM2_RC_MGF = (TPM2_RC_FMT1 + 0x008); /* mask generation function not supported */
const TPM2_RC_MODE = (TPM2_RC_FMT1 + 0x009); /* mode of operation not supported */
const TPM2_RC_TYPE = (TPM2_RC_FMT1 + 0x00A); /* the type of the value is not appropriate for the use */
const TPM2_RC_HANDLE = (TPM2_RC_FMT1 + 0x00B); /* the handle is not correct for the use */
const TPM2_RC_KDF = (TPM2_RC_FMT1 + 0x00C); /* unsupported key derivation function or function not appropriate for use */
const TPM2_RC_RANGE = (TPM2_RC_FMT1 + 0x00D); /* value was out of allowed range. */
const TPM2_RC_AUTH_FAIL = (TPM2_RC_FMT1 + 0x00E); /* the authorization HMAC check failed and DA counter incremented */
const TPM2_RC_NONCE = (TPM2_RC_FMT1 + 0x00F); /* invalid nonce size or nonce value mismatch */
const TPM2_RC_PP = (TPM2_RC_FMT1 + 0x010); /* authorization requires assertion of PP */
const TPM2_RC_SCHEME = (TPM2_RC_FMT1 + 0x012); /* unsupported or incompatible scheme */
const TPM2_RC_SIZE = (TPM2_RC_FMT1 + 0x015); /* structure is the wrong size */
const TPM2_RC_SYMMETRIC = (TPM2_RC_FMT1 + 0x016); /* unsupported symmetric algorithm or key size or not appropriate for instance */
const TPM2_RC_TAG = (TPM2_RC_FMT1 + 0x017); /* incorrect structure tag */
const TPM2_RC_SELECTOR = (TPM2_RC_FMT1 + 0x018); /* union selector is incorrect */
const TPM2_RC_INSUFFICIENT = (TPM2_RC_FMT1 + 0x01A); /* the TPM was unable to unmarshal a value because there were not enough octets in the input buffer */
const TPM2_RC_SIGNATURE = (TPM2_RC_FMT1 + 0x01B); /* the signature is not valid */
const TPM2_RC_KEY = (TPM2_RC_FMT1 + 0x01C); /* key fields are not compatible with the selected use */
const TPM2_RC_POLICY_FAIL = (TPM2_RC_FMT1 + 0x01D); /* a policy check failed */
const TPM2_RC_INTEGRITY = (TPM2_RC_FMT1 + 0x01F); /* integrity check failed */
const TPM2_RC_TICKET = (TPM2_RC_FMT1 + 0x020); /* invalid ticket */
const TPM2_RC_RESERVED_BITS = (TPM2_RC_FMT1 + 0x021); /* reserved bits not set to zero as required */
const TPM2_RC_BAD_AUTH = (TPM2_RC_FMT1 + 0x022); /* authorization failure without DA implications */
const TPM2_RC_EXPIRED = (TPM2_RC_FMT1 + 0x023); /* the policy has expired */
const TPM2_RC_POLICY_CC = (TPM2_RC_FMT1 + 0x024); /* the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented */
const TPM2_RC_BINDING = (TPM2_RC_FMT1 + 0x025); /* public and sensitive portions of an object are not cryptographically bound */
const TPM2_RC_CURVE = (TPM2_RC_FMT1 + 0x026); /* curve not supported */
const TPM2_RC_ECC_POINT = (TPM2_RC_FMT1 + 0x027); /* point is not on the required curve. */
const TPM2_RC_WARN = (0x900); /* set for warning response codes */
const TPM2_RC_CONTEXT_GAP = (TPM2_RC_WARN + 0x001); /* gap for context ID is too large */
const TPM2_RC_OBJECT_MEMORY = (TPM2_RC_WARN + 0x002); /* out of memory for object contexts */
const TPM2_RC_SESSION_MEMORY = (TPM2_RC_WARN + 0x003); /* out of memory for session contexts */
const TPM2_RC_MEMORY = (TPM2_RC_WARN + 0x004); /* out of shared objectsession memory or need space for internal operations */
const TPM2_RC_SESSION_HANDLES = (TPM2_RC_WARN + 0x005); /* out of session handles  a session must be flushed before a new session may be created */
const TPM2_RC_OBJECT_HANDLES = (TPM2_RC_WARN + 0x006); /* out of object handles. The handle space for objects is depleted and a reboot is required. NOTE This cannot occur on the reference implementation. NOTE There is no reason why an implementation would implement a design that would deplete handle space. Platform specifications are encouraged to forbid it. */
const TPM2_RC_LOCALITY = (TPM2_RC_WARN + 0x007); /* bad locality */
const TPM2_RC_YIELDED = (TPM2_RC_WARN + 0x008); /* the TPM has suspended operation on the command forward progress was made and the command may be retried. See TPM 2.0 Part 1 Multitasking. NOTE This cannot occur on the reference implementation. */
const TPM2_RC_CANCELED = (TPM2_RC_WARN + 0x009); /* the command was canceled */
const TPM2_RC_TESTING = (TPM2_RC_WARN + 0x00A); /* TPM is performing selftests */
const TPM2_RC_REFERENCE_H0 = (TPM2_RC_WARN + 0x010); /* the 1st handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H1 = (TPM2_RC_WARN + 0x011); /* the 2nd handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H2 = (TPM2_RC_WARN + 0x012); /* the 3rd handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H3 = (TPM2_RC_WARN + 0x013); /* the 4th handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H4 = (TPM2_RC_WARN + 0x014); /* the 5th handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H5 = (TPM2_RC_WARN + 0x015); /* the 6th handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_H6 = (TPM2_RC_WARN + 0x016); /* the 7th handle in the handle area references a transient object or session that is not loaded */
const TPM2_RC_REFERENCE_S0 = (TPM2_RC_WARN + 0x018); /* the 1st authorization session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S1 = (TPM2_RC_WARN + 0x019); /* the 2nd authorization session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S2 = (TPM2_RC_WARN + 0x01A); /* the 3rd authorization session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S3 = (TPM2_RC_WARN + 0x01B); /* the 4th authorization session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S4 = (TPM2_RC_WARN + 0x01C); /* the 5th session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S5 = (TPM2_RC_WARN + 0x01D); /* the 6th session handle references a session that is not loaded */
const TPM2_RC_REFERENCE_S6 = (TPM2_RC_WARN + 0x01E); /* the 7th authorization session handle references a session that is not loaded */
const TPM2_RC_NV_RATE = (TPM2_RC_WARN + 0x020); /* the TPM is rate limiting accesses to prevent wearout of NV */
const TPM2_RC_LOCKOUT = (TPM2_RC_WARN + 0x021); /* authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode */
const TPM2_RC_RETRY = (TPM2_RC_WARN + 0x022); /* the TPM was not able to start the command */
const TPM2_RC_NV_UNAVAILABLE = (TPM2_RC_WARN + 0x023); /* the command may require writing of NV and NV is not current accessible */
const TPM2_RC_NOT_USED = (TPM2_RC_WARN + 0x07F); /* this value is reserved and shall not be returned by the TPM */
const TPM2_RC_H = (0x000); /* add to a handle related error */
const TPM2_RC_P = (0x040); /* add to a parameter-related error */
const TPM2_RC_S = (0x800); /* add to a session-related error */
const TPM2_RC_1 = (0x100); /* add to a parameter handle or session-related error */
const TPM2_RC_2 = (0x200); /* add to a parameter handle or session-related error */
const TPM2_RC_3 = (0x300); /* add to a parameter handle or session-related error */
const TPM2_RC_4 = (0x400); /* add to a parameter handle or session-related error */
const TPM2_RC_5 = (0x500); /* add to a parameter handle or session-related error */
const TPM2_RC_6 = (0x600); /* add to a parameter handle or session-related error */
const TPM2_RC_7 = (0x700); /* add to a parameter handle or session-related error */
const TPM2_RC_8 = (0x800); /* add to a parameter-related error */
const TPM2_RC_9 = (0x900); /* add to a parameter-related error */
const TPM2_RC_A = (0xA00); /* add to a parameter-related error */
const TPM2_RC_B = (0xB00); /* add to a parameter-related error */
const TPM2_RC_C = (0xC00); /* add to a parameter-related error */
const TPM2_RC_D = (0xD00); /* add to a parameter-related error */
const TPM2_RC_E = (0xE00); /* add to a parameter-related error */
const TPM2_RC_F = (0xF00); /* add to a parameter-related error */


const TPM2_RH_OWNER = (0x40000001); /* K A P */
const TPM2_RH_NULL = (0x40000007); /* K A P */
const TPM2_RH_ENDORSEMENT = (0x4000000B); /* K A P */
const TPM2_RH_PLATFORM = (0x4000000C); /* K A P */
const TPM2_RS_PW = (0x40000009) /* S */


const TPM2_ECC_NONE = (0x0000);
const TPM2_ECC_NIST_P192 = (0x0001);
const TPM2_ECC_NIST_P224 = (0x0002);
const TPM2_ECC_NIST_P256 = (0x0003);
const TPM2_ECC_NIST_P384 = (0x0004);
const TPM2_ECC_NIST_P521 = (0x0005);
const TPM2_ECC_BN_P256 = (0x0010);
const TPM2_ECC_BN_P638 = (0x0011);
const TPM2_ECC_SM2_P256 = (0x0020);

const EK_CERT_NV_INDEX = 0x01c00002;


const TPM2_GENERATED_VALUE = (0xff544347); /* 0xFF TCG FF 54 43 4716 */


const TPM2_ST_ATTEST_NV = (0x8014); /* tag for an attestation structure */
const TPM2_ST_ATTEST_COMMAND_AUDIT = (0x8015); /* tag for an attestation structure */
const TPM2_ST_ATTEST_SESSION_AUDIT = (0x8016); /* tag for an attestation structure */
const TPM2_ST_ATTEST_CERTIFY = (0x8017); /* tag for an attestation structure */
const TPM2_ST_ATTEST_QUOTE = (0x8018); /* tag for an attestation structure */
const TPM2_ST_ATTEST_TIME = (0x8019); /* tag for an attestation structure */
const TPM2_ST_ATTEST_CREATION = (0x801A); /* tag for an attestation structure */
const TPM2_ST_RESERVED3 = (0x801B); /* do not use . NOTE This was previously assigned to TPM2_ST_ATTEST_NV. The tag is changed because the structure has changed */
const TPM2_ST_CREATION = (0x8021); /* tag for a ticket type */
const TPM2_ST_VERIFIED = (0x8022); /* tag for a ticket type */
const TPM2_ST_AUTH_SECRET = (0x8023); /* tag for a ticket type */
const TPM2_ST_HASHCHECK = (0x8024); /* tag for a ticket type */
const TPM2_ST_AUTH_SIGNED = (0x8025); /* tag for a ticket type */
const TPM2_ST_FU_MANIFEST = (0x8029); /* tag for a structure describing a Field Upgrade Policy */
