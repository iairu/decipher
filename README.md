# Deciphering Ransomware - Analysis and working PoC

## ToC

- [Introduction](#introduction)
  - [Dependencies](#dependencies)
  - [Included Modules (module_*) ](#included-modules-module_)
  - [RSA Functions (_rsa)](#rsa-functions-_rsa)
  - [Main Functions](#main-functions)
  - [Main Procedure](#main-procedure)
- [License](#license)

## Introduction

- To see the analytical research part of the project check the `report` folder:
  - Analysis (`analysis.md`)
  - Markdown Slides in English and Slovak (`slides_en.md`, `slides_sk.md`)
- To get the idea of how the code in `src` functions (used to capture key from memory and decipher files) see these sections below:
  - Included Modules (`modules`)
  - RSA Functions (`src/_rsa`)
  - Main Functions (`src/main`)
  - Main Procedure (How we obtain the private key)

Note: Biggest hurdle is that this only works up to Windows 7 (Windows Server 2008) and therefore DOESN'T include today's most popular Windows 10 and Windows 11 compatibility. Currently only WannaCry is supported.

### Dependencies

In order for the code to work you will need to get the OpenSSL toolkit libraries installed. A copy of `openssl` alongside a working Visual Studio solution is provided in the `wanakiwi` repository (https://github.com/gentilkiwi/wanakiwi/), I purposefully left them out (plan to add a downloader or detect existing OpenSSL install). Other modules are included.

### Included Modules (module_*)

All of these are included in the `modules` and used:

- File: Exists, Write, Read, Find
- Memory: Open, Copy, ReverseBytes
- MiniDump: Open, Close, RVAtoPTR, Stream, Copy
- String: ArgsByName
- Process: ProcInfo, PIDforName, MemInfo, NTQuerySysInfo
- Output: Echo

### RSA Functions (_rsa)

- QuickImport
- ToPrivateKeyBlob
- PubKeyBlobToRSA
- PubKeyFileToNewPubKeyEN
- SimpleModuleCryptoHKEY
- InitDefaultKey
- FreeDefaultKey
- DecryptFileWithKey
- NormalizedEntropy

### Main Functions

- wmain
- findProcess
- memoryAnalysis
- fileCallbackPublicKey
- fileCallbackWannaCry
- echoBigNum
- checkValidArchitecture
- regDeletePendingFileRenameOps

### Main Procedure

Entire procedure is in the `wmain` function; see the following comments in `main.c`:

1. Handle args e.g. private/public key on input
2. Start working from public key if we didn't get private key on input
3. Process memory or minidump
4. Entropy
5. Try to get private key from memory
6. Start working with private key

## License

See `LICENSE` file. This project began as a rewrite of memory dump and private key recovery procedures from `wanakiwi` for a more generic approach, which is intended to include future ransomware behavior. 
