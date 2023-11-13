pub mod types {
    use std::{collections::HashMap, default};

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    #[repr(u16)]
    pub enum TPM_ALG {
        ERROR = 0x0000,
        RSA = 0x0001,
        TDES = 0x0003,
        SHA = 0x0004,
        HMAC = 0x0005,
        AES = 0x0006,
        MGF1 = 0x0007,
        KEYEDHASH = 0x0008,
        XOR = 0x000A,
        SHA256 = 0x000B,
        SHA384 = 0x000C,
        SHA512 = 0x000D,
        #[default]
        NULL = 0x0010,
        SM3_256 = 0x0012,
        SM4 = 0x0013,
        RSASSA = 0x0014,
        RSAES = 0x0015,
        RSAPSS = 0x0016,
        OAEP = 0x0017,
        ECDSA = 0x0018,
        ECDH = 0x0019,
        ECDAA = 0x001A,
        SM2 = 0x001B,
        ECSCHNORR = 0x001C,
        ECMQV = 0x001D,
        KDF1_SP800_56A = 0x0020,
        KDF2 = 0x0021,
        KDF1_SP800_108 = 0x0022,
        ECC = 0x0023,
        SYMCIPHER = 0x0025,
        CAMELLIA = 0x0026,
        SHA3_256 = 0x0027,
        SHA3_384 = 0x0028,
        SHA3_512 = 0x0029,
        CMAC = 0x003F,
        CTR = 0x0040,
        OFB = 0x0041,
        CBC = 0x0042,
        CFB = 0x0043,
        ECB = 0x0044,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    #[repr(u16)]
    pub enum TPM_ECC_CURVE {
        #[default]
        NONE = 0x0000,
        NIST_P192 = 0x0001,
        NIST_P224 = 0x0002,
        NIST_P256 = 0x0003,
        NIST_P384 = 0x0004,
        NIST_P521 = 0x0005,
        BN_P256 = 0x0010,
        BN_P638 = 0x0011,
        SM2_P256 = 0x0020,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPM_HANDLE(u32);

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMI_RH_HIERARCHY(TPM_HANDLE);

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMS_COMMAND_HANDLES_CREATE_PRIMARY {
        pub primaryHandle: TPMI_RH_HIERARCHY,
    }

    type TPM2B_DIGEST = Vec<u8>;
    type TPM2B_SENSITIVE_CREATE = Vec<u8>;
    type TPM2B_DATA = Vec<u8>;
    type TPM2B_PUBLIC_KEY_RSA = Vec<u8>;
    type TPM2B_ECC_PARAMETER = Vec<u8>;

    pub type TPM_ALG_ID = u16;
    pub type TPMI_ALG_SYM_OBJECT = TPM_ALG_ID;
    pub type TPMI_TDES_KEY_BITS = TPM_ALG_ID;
    pub type TPMI_AES_KEY_BITS = TPM_ALG_ID;
    pub type TPMI_SM4_KEY_BITS = TPM_ALG_ID;
    pub type TPMI_CAMELLIA_KEY_BITS = TPM_ALG_ID;
    pub type TPM_KEY_BITS = u16;
    pub type TPMI_ALG_HASH = TPM_ALG_ID;
    pub type TPMI_ALG_SYM_MODE = TPM_ALG_ID;
    pub type TPMI_ALG_ECC_SCHEME = TPM_ALG_ID;
    pub type TPMI_ECC_CURVE = TPM_ALG_ID;
    pub type TPMI_ALG_KDF = TPM_ALG_ID;
    pub type TPMI_ALG_PUBLIC = TPM_ALG_ID;
    pub type TPMI_RSA_KEY_BITS = TPM_KEY_BITS;

    // #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
    // #[repr(u16)]
    // pub enum TPMU_SYM_KEY_BITS {
    //     tdes(TPMI_TDES_KEY_BITS) = TPM_ALG::TDES as u16,
    //     aes(TPMI_AES_KEY_BITS) = TPM_ALG::AES as u16,
    //     sm4(TPMI_SM4_KEY_BITS) = TPM_ALG::SM4 as u16,
    //     camellia(TPMI_CAMELLIA_KEY_BITS) = TPM_ALG::CAMELLIA as u16,
    //     sym(TPM_KEY_BITS) = 0xffff,
    //     xor(TPMI_ALG_HASH) = TPM_ALG::XOR as u16,
    //     #[default]
    //     null = TPM_ALG::NULL as u16,
    // }

    // #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
    // #[repr(u16)]
    // pub enum TPMU_SYM_MODE {
    //     tdes(TPMI_ALG_SYM_MODE) = TPM_ALG::TDES as u16,
    //     aes(TPMI_ALG_SYM_MODE) = TPM_ALG::AES as u16,
    //     sm4(TPMI_ALG_SYM_MODE) = TPM_ALG::SM4 as u16,
    //     camellia(TPMI_ALG_SYM_MODE) = TPM_ALG::CAMELLIA as u16,
    //     sym(TPMI_ALG_SYM_MODE) = 0xffff as u16,
    //     xor = TPM_ALG::XOR as u16,
    //     #[default]
    //     null = TPM_ALG::NULL as u16,
    // }

    // #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
    // #[repr(u16)]
    // pub enum TPMU_SYM_DETAILS {
    //     tdes = TPM_ALG::TDES as u16,
    //     aes = TPM_ALG::AES as u16,
    //     sm4 = TPM_ALG::SM4 as u16,
    //     camellia = TPM_ALG::CAMELLIA as u16,
    //     sym = 0xffff as u16,
    //     xor = TPM_ALG::XOR as u16,
    //     #[default]
    //     null = TPM_ALG::NULL as u16,
    // }

    // #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    // pub enum TPMS_RSA_PARMS {
    //     pub scheme: TPMI_ALG_RSA_SCHEME,
    //     pub details: TPMU_ASYM_SCHEME,
    // }

    type TPMT_RSA_SCHEME = TPMU_ASYM_SCHEME; // selected by TPMI_ALG_RSA_SCHEME

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMS_RSA_PARMS {
        pub symmetric: TPMT_SYM_DEF_OBJECT, // TODO TPMT_SYM_DEF_OBJECT+
        pub scheme: TPMT_RSA_SCHEME,        // TODO TPMT_SYM_DEF_OBJECT+
        pub keyBits: TPMI_RSA_KEY_BITS,
        pub exponent: u32,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMT_SYM_DEF_OBJECT {
        // TODO selector: pub algorithm: TPMI_ALG_SYM_OBJECT,
        // pub keyBits: TPMU_SYM_KEY_BITS,
        // pub mode: TPMU_SYM_MODE,
        // pub details: TPMU_SYM_DETAILS,
        pub sym: TPMU_SYM_DEF_OBJECT, // combines unions keyBits/mode/details
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    #[repr(u16)]
    pub enum TPMU_SYM_DEF_OBJECT {
        tdes {
            keyBits: TPMI_TDES_KEY_BITS,
            mode: TPMI_ALG_SYM_MODE,
        } = TPM_ALG::TDES as u16,
        aes {
            keyBits: TPMI_AES_KEY_BITS,
            mode: TPMI_ALG_SYM_MODE,
        } = TPM_ALG::AES as u16,
        sm4 {
            keyBits: TPMI_SM4_KEY_BITS,
            mode: TPMI_ALG_SYM_MODE,
        } = TPM_ALG::SM4 as u16,
        camellia {
            keyBits: TPMI_CAMELLIA_KEY_BITS,
            mode: TPMI_ALG_SYM_MODE,
        } = TPM_ALG::CAMELLIA as u16,
        // sym {
        //     keyBits: TPM_KEY_BITS,
        //     mode: TPMI_ALG_SYM_MODE,
        // } = 0xffff as u16,
        xor {
            keyBits: TPMI_ALG_HASH,
        } = TPM_ALG::XOR as u16,
        #[default]
        null = TPM_ALG::NULL as u16,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMS_SCHEME_HASH {
        pub hashAlg: TPMI_ALG_HASH,
    }

    pub type TPMS_KEY_SCHEME_ECDH = TPMS_SCHEME_HASH;
    pub type TPMS_KEY_SCHEME_ECMQV = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_ECDAA = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_ECDSA = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_ECSCHNORR = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_RSAPSS = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_RSASSA = TPMS_SCHEME_HASH;
    pub type TPMS_SIG_SCHEME_SM2 = TPMS_SCHEME_HASH;
    pub type TPMS_ENC_SCHEME_OAEP = TPMS_SCHEME_HASH;
    pub type TPMS_ENC_SCHEME_RSAES = TPMS_SCHEME_HASH;

    #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
    #[repr(u16)]
    pub enum TPMU_ASYM_SCHEME {
        ecdh(TPMS_KEY_SCHEME_ECDH) = TPM_ALG::ECDH as u16,
        ecmqv(TPMS_KEY_SCHEME_ECMQV) = TPM_ALG::ECMQV as u16,
        ecdaa(TPMS_SIG_SCHEME_ECDAA) = TPM_ALG::ECDAA as u16,
        ecdsa(TPMS_SIG_SCHEME_ECDSA) = TPM_ALG::ECDSA as u16,
        ecschnorr(TPMS_SIG_SCHEME_ECSCHNORR) = TPM_ALG::ECSCHNORR as u16,
        rsapss(TPMS_SIG_SCHEME_RSAPSS) = TPM_ALG::RSAPSS as u16,
        rsassa(TPMS_SIG_SCHEME_RSASSA) = TPM_ALG::RSASSA as u16,
        sm2(TPMS_SIG_SCHEME_SM2) = TPM_ALG::SM2 as u16,
        oaep(TPMS_ENC_SCHEME_OAEP) = TPM_ALG::OAEP as u16,
        rsaes(TPMS_ENC_SCHEME_RSAES) = TPM_ALG::RSAES as u16,
        anySig(TPMS_SCHEME_HASH) = 0xffff,
        #[default]
        null = TPM_ALG::NULL as u16,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMT_ECC_SCHEME {
        // "details": "scheme",
        pub scheme: TPMI_ALG_ECC_SCHEME,
        pub details: TPMU_ASYM_SCHEME,
    }

    pub type TPMS_SCHEME_MGF1 = TPMS_SCHEME_HASH;
    pub type TPMS_SCHEME_KDF1_SP800_108 = TPMS_SCHEME_HASH;
    pub type TPMS_SCHEME_KDF1_SP800_56A = TPMS_SCHEME_HASH;
    pub type TPMS_SCHEME_KDF2 = TPMS_SCHEME_HASH;

    #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
    #[repr(u16)]
    pub enum TPMU_KDF_SCHEME {
        mgf1(TPMS_SCHEME_MGF1) = TPM_ALG::MGF1 as u16,
        kdf1_sp800_108(TPMS_SCHEME_KDF1_SP800_108) = TPM_ALG::KDF1_SP800_108 as u16,
        kdf1_sp800_56a(TPMS_SCHEME_KDF1_SP800_56A) = TPM_ALG::KDF1_SP800_56A as u16,
        kdf2(TPMS_SCHEME_KDF2) = TPM_ALG::KDF2 as u16,
        #[default]
        null = TPM_ALG::NULL as u16,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMT_KDF_SCHEME {
        // "details": "scheme",
        pub scheme: TPMI_ALG_KDF,
        pub details: TPMU_KDF_SCHEME,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMS_ECC_PARMS {
        pub symmetric: TPMT_SYM_DEF_OBJECT,
        pub scheme: TPMT_ECC_SCHEME,
        pub curveID: TPMI_ECC_CURVE,
        pub kdf: TPMT_KDF_SCHEME,
    }

    // #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    // #[repr(u16)]
    // pub enum TPMU_PUBLIC_PARMS {
    //     // _selected_by = {
    //     //     "keyedHashDetail": TPM_ALG.KEYEDHASH,
    //     //     "symDetail": TPM_ALG.SYMCIPHER,
    //     //     "rsaDetail": TPM_ALG.RSA,
    //     //     "eccDetail": TPM_ALG.ECC,
    //     //     "asymDetail": None,
    //     // }

    //     //keyedHashDetail: TPMS_KEYEDHASH_PARMS
    //     //symDetail: TPMS_SYMCIPHER_PARMS
    //     //rsaDetail(TPMS_RSA_PARMS) = TPM_ALG::RSA as u16,
    //     eccDetail(TPMS_ECC_PARMS) = TPM_ALG::ECC as u16,
    //     //asymDetail: TPMS_ASYM_PARMS
    // }

    // impl Default for TPMU_PUBLIC_PARMS {
    //     fn default() -> TPMU_PUBLIC_PARMS {
    //         TPMU_PUBLIC_PARMS::eccDetail(Default::default())
    //     }
    // }
    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMS_ECC_POINT {
        pub x: TPM2B_ECC_PARAMETER,
        pub y: TPM2B_ECC_PARAMETER,
    }

    // #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    // #[repr(u16)]
    // pub enum TPMU_PUBLIC_ID {
    //     // _selected_by = {
    //     //     "keyedHash": TPM_ALG.KEYEDHASH,
    //     //     "sym": TPM_ALG.SYMCIPHER,
    //     //     "rsa": TPM_ALG.RSA,
    //     //     "ecc": TPM_ALG.ECC,
    //     //     "derive": None,
    //     // }

    //     //keyedHash: TPM2B_DIGEST
    //     //sym: TPM2B_DIGEST
    //     rsa(TPM2B_PUBLIC_KEY_RSA) = TPM_ALG::RSA as u16,
    //     ecc(TPMS_ECC_POINT) = TPM_ALG::ECC as u16,
    //     //derive: TPMS_DERIVE
    // }

    // impl Default for TPMU_PUBLIC_ID {
    //     fn default() -> TPMU_PUBLIC_ID {
    //         TPMU_PUBLIC_ID::ecc(Default::default())
    //     }
    // }

    pub type TPMA_OBJECT = u32; // TODO bitfield

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    #[repr(u16)]
    pub enum TPMU_PUBLIC {
        // TODO
        // keyedHash {
        //     nameAlg: TPMI_ALG_HASH,
        //     objectAttributes: u32,
        //     authPolicy: TPM2B_DIGEST,
        //     parameters: TPMS_KEYEDHASH_PARMS,
        //     unique: TPM2B_DIGEST,
        // } = TPM_ALG.KEYEDHASH as u16,
        // sym {
        //     nameAlg: TPMI_ALG_HASH,
        //     objectAttributes: u32,
        //     authPolicy: TPM2B_DIGEST,
        //     parameters: TPMS_SYMCIPHER_PARMS,
        //     unique: TPM2B_DIGEST,
        // } = TPM_ALG.SYMCIPHER as u16,
        rsa {
            nameAlg: TPMI_ALG_HASH,
            objectAttributes: u32,
            authPolicy: TPM2B_DIGEST,
            parameters: TPMS_RSA_PARMS,
            unique: TPM2B_PUBLIC_KEY_RSA,
        } = TPM_ALG::RSA as u16,
        ecc {
            nameAlg: TPMI_ALG_HASH,
            objectAttributes: u32,
            authPolicy: TPM2B_DIGEST,
            parameters: TPMS_ECC_PARMS,
            unique: TPMS_ECC_POINT,
        } = TPM_ALG::ECC as u16,
        // what about unselectable TPMU_PUBLIC_PARMS.asymDetail and TPMU_PUBLIC_ID.derive?
    }

    impl Default for TPMU_PUBLIC {
        fn default() -> TPMU_PUBLIC {
            // TODO why does ..Default::default() result in an error?
            TPMU_PUBLIC::ecc {
                nameAlg: Default::default(),
                objectAttributes: Default::default(),
                authPolicy: Default::default(),
                parameters: Default::default(),
                unique: Default::default(),
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPMT_PUBLIC {
        // TODO selector: pub type_: TPMI_ALG_PUBLIC,
        pub public: TPMU_PUBLIC,
        // pub nameAlg: TPMI_ALG_HASH, // TPMI_ALG_HASH,  # TODO is optional
        // pub objectAttributes: u32,  // TPMA_OBJECT,
        // pub authPolicy: TPM2B_DIGEST,
        // pub parameters: TPMU_PUBLIC_PARMS,
        // pub unique: TPMU_PUBLIC_ID,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
    pub struct TPM2B_PUBLIC {
        pub size: u16,
        pub publicArea: TPMT_PUBLIC,
    }

    // pub struct TPMS_COMMAND_PARAMS_CREATE_PRIMARY {
    //     inSensitive: TPM2B_SENSITIVE_CREATE,
    //     inPublic: TPM2B_PUBLIC,
    //     outsideInfo: TPM2B_DATA,
    //     creationPCR: TPML_PCR_SELECTION,
    // }

    // pub struct Command<Handles, Params> {
    //     pub tag: u16,
    //     pub size: u32,
    //     //pub cc: u32,
    //     pub handles: Handles,
    //     pub params: Params,
    // }

    // pub type CreatePrimaryComand =
    //     Command<TPMS_COMMAND_HANDLES_CREATE_PRIMARY, TPMS_COMMAND_PARAMS_CREATE_PRIMARY>;
}

fn is_normal<T: Sized + Send + Sync + Unpin>() {}

#[test]
fn normal_types() {
    is_normal::<types::TPMT_PUBLIC>();
    // TODO do this for all pub types
}
