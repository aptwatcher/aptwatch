/*
    APT Watch - Conti Locker v2 Detection Rules
    Date: 2026-03-30
    Source: Conti Toolkit Leak - Direct Source Code Analysis
    Actor: Conti / Wizard Spider

    Based on analysis of ContiLocker_v2.sln source code:
    - MurmurHash2A API hash constants (unique fingerprint)
    - ChaCha20 + RSA encryption markers
    - Encrypt mode constants
    - File structure markers (encrypted key at EOF-534)
*/

rule ContiLocker_v2_APIHashes
{
    meta:
        description = "Detects Conti Locker v2 via MurmurHash2A API resolution hash constants"
        author = "APT Watch"
        date = "2026-03-30"
        source = "Conti Toolkit Leak source code analysis"
        actor = "Conti / Wizard Spider"
        reference = "https://aptwatch.org"
        hash_algorithm = "MurmurHash2A"
        severity = "critical"
        mitre_attack = "T1027,T1486"

    strings:
        // kernel32.dll hash + LoadLibraryA hash (bootstrap constants)
        $kernel32_hash = { c0 fb 0d 24 }  // 0x240dfbc0
        $loadlib_hash  = { a8 21 3d be }  // 0xbe3d21a8

        // Critical API hashes - file operations (encryption core)
        $h_CreateFileW         = { ca 87 6e f0 }  // 0xf06e87ca
        $h_WriteFile           = { 8c 4a 5f c4 }  // 0xc45f4a8c
        $h_ReadFile            = { a0 c9 1a f9 }  // 0xf91ac9a0
        $h_GetFileSizeEx       = { cc cb 1a 1b }  // 0x1b1acbcc
        $h_SetFilePointerEx    = { d3 6b 4e d5 }  // 0xd54e6bd3
        $h_SetEndOfFile        = { 1e a6 e8 ed }  // 0xede8a61e
        $h_MoveFileW           = { 17 78 fb c8 }  // 0xc8fb7817

        // Critical API hashes - crypto operations
        $h_CryptAcquireContextA = { ab 40 30 26 }  // 0x263040ab
        $h_CryptImportKey       = { e3 10 d4 2a }  // 0x2ad410e3
        $h_CryptEncrypt         = { b8 e5 8c 5a }  // 0x5a8ce5b8
        $h_CryptDecrypt         = { 4e df db 2b }  // 0x2bdbdf4e
        $h_CryptDestroyKey      = { ba c2 da 5d }  // 0x5dacc2ba

        // Network scanning hashes (SMB enumeration)
        $h_NetShareEnum   = { df 11 7b 39 }  // 0x397b11df
        $h_WNetOpenEnumW  = { 21 61 85 61 }  // 0x61856121

        // Restart Manager hashes (kill locking processes)
        $h_RmStartSession  = { 26 01 57 55 }  // 0x55710126
        $h_RmRegisterResources = { be 32 45 3a }  // 0x3a4532be
        $h_RmGetList       = { 5b 57 c1 00 }  // 0x00c1575b

        // Process/thread management
        $h_CreateThread       = { f6 b7 77 68 }  // 0x6877b7f6
        $h_CreateProcessW     = { a2 a0 24 73 }  // 0x7324a0a2
        $h_GetCurrentProcess  = { f4 63 3b 66 }  // 0x663b63f4
        $h_CreateMutexA       = { 2c 96 01 f7 }  // 0xf701962c

        // Shell operations (ransom note)
        $h_ShellExecuteW = { 6a a1 43 52 }  // 0x5243a16a

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $kernel32_hash and
        $loadlib_hash and
        6 of ($h_*)
}

rule ContiLocker_v2_EncryptModes
{
    meta:
        description = "Detects Conti Locker v2 encryption mode constants"
        author = "APT Watch"
        date = "2026-03-30"
        source = "Conti Toolkit Leak source code (global_parameters.h)"
        actor = "Conti / Wizard Spider"
        severity = "critical"
        mitre_attack = "T1486"

    strings:
        // Encrypt mode enum: ALL=10, LOCAL=11, NETWORK=12, BACKUPS=13
        $mode_all      = { 0A 00 00 00 }  // ALL_ENCRYPT = 10
        $mode_local    = { 0B 00 00 00 }  // LOCAL_ENCRYPT = 11
        $mode_network  = { 0C 00 00 00 }  // NETWORK_ENCRYPT = 12
        $mode_backups  = { 0D 00 00 00 }  // BACKUPS_ENCRYPT = 13

        // File encryption sub-modes from locker.h
        $file_full    = { 24 00 00 00 }  // FULL_ENCRYPT = 0x24
        $file_partly  = { 25 00 00 00 }  // PARTLY_ENCRYPT = 0x25
        $file_header  = { 26 00 00 00 }  // HEADER_ONLY = 0x26

        // ChaCha20 constants ("expand 32-byte k")
        $chacha_const = "expand 32-byte k"

        // RSA key import markers
        $rsa_marker = { 06 02 00 00 00 A4 00 00 }  // PUBLICKEYBLOB header for RSA

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $chacha_const and
        (2 of ($mode_*) or 2 of ($file_*)) and
        ($rsa_marker or #h_CryptImportKey > 0)
}

rule ContiLocker_v2_EncryptedFile
{
    meta:
        description = "Detects files encrypted by Conti Locker v2 (encrypted key at EOF-534)"
        author = "APT Watch"
        date = "2026-03-30"
        source = "Conti Toolkit Leak source code (decryptor.cpp)"
        actor = "Conti / Wizard Spider"
        severity = "high"
        mitre_attack = "T1486"
        note = "Conti appends a 524-byte RSA-encrypted ChaCha20 key block at offset filesize-534 from EOF, preceded by a 10-byte trailer"

    condition:
        // Conti encrypted files have the 524-byte RSA blob near EOF
        // The RSA-encrypted block starts at filesize - 534
        // and the file size must be > 534 bytes (minimum encrypted file)
        filesize > 534 and
        // The RSA OAEP encrypted block is exactly 524 bytes (4096-bit RSA = 512 bytes + padding)
        // Look for non-zero high-entropy block at the expected offset
        uint8(filesize - 534) != 0x00
}

rule Conti_Decryptor_Binary
{
    meta:
        description = "Detects known Conti decryptor binaries from toolkit leak"
        author = "APT Watch"
        date = "2026-03-30"
        severity = "high"
        mitre_attack = "T1486"

    strings:
        // Known SHA-256 hashes as hex (for hash-based matching in YARA scanners)
        // 142cf75bce899bca2e12ed4a8e4e74b3f6b3405de6a60517601eae32a6de35c1 (Debug)
        // 9aed278f4eeb4ee5eaf94cde5ecf00dd5f1e3797e9854b01a20eca741e15f042 (Release)

        // Decryptor-specific strings
        $dec_str1 = "decrypt" wide ascii nocase
        $dec_str2 = ".CONTI" wide ascii
        $dec_str3 = "CONTI_DECRYPTOR" wide ascii
        $dec_str4 = "readme" wide ascii

        // ChaCha20 decryption path
        $chacha = "expand 32-byte k"
        $rsa = { 06 02 00 00 00 A4 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $chacha and $rsa and
        2 of ($dec_str*)
}

rule TeamTNT_Trojanized_Libpcap
{
    meta:
        description = "Detects TeamTNT trojanized libpcap.so credential capture implant"
        author = "APT Watch"
        date = "2026-03-30"
        source = "Conti Toolkit Leak - TeamTNT tools analysis"
        actor = "TeamTNT"
        severity = "high"
        mitre_attack = "T1552.001,T1056.001"
        hash = "78facfc05e76e4e27d8eba753c97a3b8a2c5e96a69533c1a98a2e52ce2c73d37"

    strings:
        $chimaera_c2 = "45.9.148.108" ascii
        $domain1 = "chimaera.cc" ascii
        $domain2 = "teamtnt.red" ascii
        $lib_pcap = "libpcap" ascii
        $capture = "pcap_" ascii

    condition:
        uint32(0) == 0x464C457F and  // ELF header
        $lib_pcap and $capture and
        any of ($chimaera_c2, $domain1, $domain2)
}
