# Ondrej Špánik 

**DECIPHERING RANSOMWARE**

December 2024 BIT@FIIT.STU  

---

## Intro
- This is not about stopping, hacking, or debugging
- It's about creating a decryption method for data recovery
  - How does ransomware work?
  - How to decrypt the algorithm? Does it have vulnerabilities?
  - How to bypass the whole process and decrypt the undecryptable?

---

## Reverse Engineering
- **Tools**: Unpacme, VM, IDA, Ghidra
- **Techniques**:
  - Dynamic imports (libraries)
  - Incremental labeling
  - Pseudocode synchronization
  - Windows API documentation

---

## WannaCry
- Creates a service via TaskScheduler, encrypts every new disk
- KillSwitch only if the internet and a given domain are working
- Spreading also via RDP, uses the SMB exploit EternalBlue
- Combination of RSA and AES

---

## Reality
- **90%+ of ransomware** is a combination of RSA and AES:
  - AES: fast :), symmetric :(
  - RSA: slow :(, asymmetric :)
  - Together: almost undecryptable >_<

---

## Algorithm
1. File tree
2. Recursively for each file:
   - Generation of symmetric AES (correct types needed!)
   - Encryption of the file using AES
   - Encryption of the AES key using RSA
   - Appending the key to the file

---

## RSA
- **Principle**:
  - Product of large prime numbers `p * q = n`
  - `n`: public (modulus)
  - `e`: mostly a known value (the public key is the pair `(e,n)`)
  - If we know `p` and `q`, we can calculate `d` (the private key is the pair `(d,n)`)
  - Strength of RSA: the inability to find `d`, or to factorize `n` back to `p` and `q` in human time
    - 2024: RSA-2048 ideal in billions of years, RSA-1024 weak and a matter of months-years

---

## RSA Vulnerabilities
- I identified the following:
  - Shared `p` or `q` between multiple keys
  - Close `p` and `q`: brute force factorization
  - Encryption of 0 or 1 always has the same output
- Most ransomware uses OpenSSL (vulnerabilities do not apply) :(
- Only the capture of the private key remains (rare)

---

## Memory Dump (src/main.c)
- Capturing the private key while it is in RAM
  - Ransomware stores the public key `(e,n)` locally:
    - `n` (modulus) we know
    - `e` we know
  - We need to find `p`, `q` as prime numbers equal to `n`
  - Try the key
- Saving the key and decryption with custom software or ransomware

