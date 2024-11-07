Slovak University of Technology in Bratislava

Faculty of Informatics and Information Technologies

Bc. Ondrej Špánik

# Deciphering ransomware

November 2024

---

# Topic introduction

This topic should focus on decrypting ransomware. To clarify: Decrypting ransomware is not simply stopping, hacking, or debugging, but developing a decryption method to recover data.

By decryption of ransomware I understand the successful attempt to get back data by creating a `decrypt` function for an existing ransomware without knowing the private key. Different algorithms can be used, however RSA is most common, almost ubiquitous among known ransomware.

The complete list of ransomware I plan to select from is: Cerber, Cryptowall, Djvu, Jigsaw, LockBit, Locky, Mamba, Petrwrap, Petya, NotPetya, Radamant, Satana, Sodinokibi, TearDrop, TeslaCrypt, Thanos, WannaCry, WannaCryPlus, GoldenEye, BadRabbit, Annabelle, MonsterV1, MonsterV2, Pikachu. I have binaries for each from two GitHub repositories: kh4sh3i/Ransomware-Samples and ThatSINEWAVE/Malware-Samples.

For monitoring the state of ransomware in the world, the Ransomlook.io website is suitable (similar to RansomWatch).

---

## Common ransomware encryption algorithms

RSA is heavily favored in ransomware due to its asymmetric nature, allowing attackers to encrypt data with a publicly available key while keeping the decryption key private. This makes it extremely difficult for victims to recover their data without paying the ransom. While symmetric algorithms like AES are faster, they require a secure method for sharing the key, which poses a significant challenge for attackers. [1]

Each ransomware's encryption and decryption status:

| Ransomware | Encryption Method | Decryptor Availability |
|------------|------------------|----------------------|
| Cerber | RSA-2048 + RC4 | Decryptor available for V1 [2] |
| CryptoWall | RSA-2048 + AES-256 | No decryption tool available |
| Djvu | RSA-1024 + AES-256 | Decryptor available for some variants [2] |
| Jigsaw | AES-128 | Decryptor available [2] |
| LockBit | RSA-2048 + AES-256 | Decryptor available for v3.0 [2] |
| Locky | RSA-2048 + AES-128 (ECB mode) | No decryption tool available |
| Mamba | Full disk encryption with DiskCryptor | No decryption tool available |
| Petrwrap | Modified Petya using custom encryption | No decryption tool available |
| Petya | RSA-2048 + Salsa20 | Partial decryptor available for some variants [2] |
| NotPetya | RSA-2048 + Salsa20 | No decryption possible |
| Radamant | RSA + AES | Decryptor available [2] |
| Satana | RSA-2048 + AES-256 | No decryption tool available |
| Sodinokibi | RSA-2048 + Salsa20 | Decryptor available for REvil/Sodinokibi variant [2] |
| TearDrop | Custom encryption | No public decryptor available |
| TeslaCrypt | RSA + AES-256 | Master key released; decryptors available for all major versions [2] |
| Thanos | RSA-2048 + AES-256 | No decryption tool available |
| WannaCry | RSA-2048 + AES-128 | No universal decryption tool available |
| WannaCryPlus | RSA-2048 + AES-128 | No decryption tool available |
| GoldenEye | RSA-2048 + Salsa20 | No decryption tool available |
| BadRabbit | RSA-2048 + AES-128 | No decryption tool available |
| Annabelle | Custom weak encryption | Decryptable [2] |
| MonsterV1 | Unknown | Decryptor not found on NoMoreRansom |
| MonsterV2 | Unknown | Decryptor not found on NoMoreRansom |
| Pikachu | Unknown | Decryptor not found on NoMoreRansom |

Of these only a small percentage is potentially brute-forceable due to weak encryption. Rest uses strong cryptography (unless it's improperly implemented) making brute force attacks infeasible.

Locky is impossible to decrypt (RSA-2048 + AES-128 cipher with ECB), Cryptowall is an offshoot of CryptoLocker ransomware that uses RSA-2048 (so again a problem with complexity in case of bruteforce private key search). RSA encryption will be a problem in most cases, as it is quite common for ransomware to use a public+private key combination (similar to SSH), where the private key is of course not present on the infected infrastructure.

---

## How ransomware usually gets "decrypted"

Decryption of ransomware-encrypted files often exploits flaws in the malware's implementation rather than breaking the underlying cryptographic algorithms. Common vulnerabilities include weak key generation, insecure key storage, or the presence of a "kill switch" that disables encryption under specific conditions. In some instances, law enforcement agencies have seized servers containing decryption keys, enabling the development of decryption tools [2].

Researchers may also identify vulnerabilities that allow them to bypass encryption or recover keys. Occasionally, attackers release decryption keys, either due to pressure from authorities or a change of heart. If affected by ransomware, it's advisable to back up encrypted files and monitor developments, as decryption tools may become available over time. An extensive list of decryption tools, developed in cooperation with Europol, is available on the No More Ransom website [2]. 

| Backdoor Type                  | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| Key Storage Vulnerabilities    | Encryption keys stored locally or transmitted insecurely.                   |
| Hardcoded Keys or Master Keys  | Master decryption key embedded in ransomware code.                          |
| Poor Random Number Generation  | Weak randomness leading to predictable keys.                                |
| Offline Encryption Backdoors   | Default keys used when ransomware is offline.                               |
| Kill Switches                  | Mechanisms that disable encryption under specific conditions.               |
| Exposed Decryption Keys        | Keys leaked from insecure servers or tools.                                 |
| Weak Implementation of Algorithms | Flawed coding leading to exploitable vulnerabilities.                    |
| Attacker Backdoors             | Hidden methods for attackers to bypass encryption.                          |
| Failure to Delete Keys         | Encryption keys left in memory or temporary files.                          |
| Pressure-Induced Releases      | Attackers releasing keys due to external pressure.                          |

---

## Introduction to some ransomware strains

### Locky

This particular ransomware stain was wreaking havoc around 8-9 years ago (2015-2016). Registry contains values for keys "id", "paytext" and "pubkey" in `HKEY_CURRENT_USER\Software\Locky`. Ransomware changes the desktop wallpaper to notify the user about fate of their files and how to pay for the ransom. It is possible to recover files by booting into Safe Mode and restoring to a previous state using the Windows System Restore utility, however it's also common for people to not have any recent System Restore saves. Otherwise you can also use a utility available online or clean the temporary files in `AppData\Local\Temp` to remove the ransomware binary, which is saved under a randomized filename with `exe` extension, from your computer. It's also recommended to renew registry permissions using a special utility `subinacl` [3] available online and the following lines (after a full registry backup has been performed):

```bash
subinacl /subkeyreg HKEY_LOCAL_MACHINE /setowner=Administrators
subinacl /subkeyreg HKEY_CURRENT_USER /setowner=Administrators
subinacl /subkeyreg HKEY_CLASSES_ROOT /setowner=Administrators
subinacl /subdirectories %SystemDrive% /setowner=Administrators

subinacl /subkeyreg HKEY_LOCAL_MACHINE /grant=system=f
subinacl /subkeyreg HKEY_CURRENT_USER /grant=system=f
subinacl /subkeyreg HKEY_CLASSES_ROOT /grant=system=f
subinacl /subdirectories %SystemDrive% /grant=system=f
```

Currently, the NoMoreRansom project [2] contains decryption tools for `AutoLocky` and `Pylocky` strains of ransomware, however these are different from the original `Locky`. Pylocky pretends to be Locky and is packaged in PyInstaller, with first reference being made in 2018 [4]. AutoLocky also tries to impersonate Locky, being created using AutoIt scripting language (similar to AutoHotkey) and released sometime in 2016 [5].

We monitored Locky's behavior on an isolated VM instance of Windows with Wireshark running in the background:

Time Behavior
0s Double-clicked Locky.exe on desktop by user
45s Locky.exe disappears
60s Stream of DNS requests to multiple domains like gybwjfnlf.nl, icmgjlcwdagup.fr, neowblqxfcuwyjx.ru, btlgjec.eu and sjekmb.pm
120s Stream still continues, ransomware can't connect because there is no internet connection

Seems we will not be getting our files compromised considering that the Locky ransomware appears to require a working internet connection.

### WannaCry

Perhaps the most infamous of them all and one that actually came with a kill switch. While WannaCry no longer spreads, you will not have any luck decrypting your files here either [2]. Only other ransomware that bears a similar name and can be decrypted is called `WannaCryFake`; I wonder how they came up with such a dumb name.

WannaCry started spreading on 12 May 2017 thanks to leaked EternalBlue NSA exploit (affecting SMB also known as Samba [6], which had at least 5 RCE CVEs in that same year) and there are multiple documentaries showcasing how devastating WannaCry was [7]. Only a few countries, mostly ones in Africa, seem to have avoided its fallout [7]. Microsoft even had to release a security update for Windows XP well past its sunset date for regular customers, however Windows Embedded from 2009 which was based on Windows XP continued receiving updates until April 2019 [8] and you could get these on regular Windows XP using a registry hack, so I would not consider this support that surprising.

Main reason for why WannaCry was so devastating is that it tries to spread over network after encryption of its host machine. The attack lasted roughly 7 hours until the kill switch was discovered and activated by a security researcher Marcus Hutchins. Those 7 hours were enough to infect majority of world's countries. Later in 2018 a new variant forced TSMC to temporarily shut down its highly advanced facilities [9]. Companies affected by the original strain include ones in Russia, U.S., a faculty hospital in Nitra, Slovakia and so on. It is believed the virus originated in North Korea with Lazarus Group [10] being the main suspects.

## Cryptowall

If you see your files suddenly gained an additional `.abc` extensions, chances are it is the doing of Cryptowall. This ransomware has been active in 2014 [11] with a 4.0 feature update in 2015 [12] (that's a lot of versions). One of the way it spread was by being disguised as a voicemail with `.wav` audio file icon, while actually being a `.scr` Windows screensaver file [13]. After encryption a Notepad popup appears with information about paying the ransom and a slightly more colorful html page pops up with equivalent information at the same time as well [13]. In a demonstration found on YouTube only document files were encrypted and image files were left untouched [13]. At the time when this ransomware released a Bitcoin ransom payment was available for 500USD on a website linked utilizing 3 different HTTP TOR proxy service mirrors in the notepad/html file, which also stated how many files were encrypted and a live timer of how much time you had left until the ransom would double in price, quite creative. In addition the same site offered to decrypt a single file for free, perhaps to gain their trust. So far the best setup from the ransomware I've seen. These guys basically created the ideal environment for people to pay out of fear that they will run out of time and by gaining at least some trust through single file decryption. There were even payment installments available so you would not have to pay all at once.

Currently in late 2024, there is no decryption tool available on NoMoreRansom for this ransomware either [2]. Your best bet is to remove the ransomware binary by installing anti-virus software, especially anti-virus with "anti-ransomware" features and running a computer scan [14], then restore your files using Windows System Restore, that is if you have any restore points saved.

---

# RSA

In order to try decrypting ransomware, we first have to understand how encryption works and some vulnerabilities it may posess.

RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm named after its creators Ron Rivest, Adi Shamir, and Leonard Adleman who developed it in 1977 [15]. The security of RSA relies on the mathematical difficulty of factoring the product of two large prime numbers - once these prime numbers are multiplied together to create the public key, it becomes computationally infeasible to determine the original prime numbers, which are needed to create the private key. Even with today's most powerful supercomputers, factoring the large prime numbers used in RSA-2048 and RSA-4096 remains practically impossible.

## Analysis of a simple yet lethal RSA ransomware

Let's examine a simple RSA ransomware's behavior within a controlled environment, including its interaction with the file system and system resources. This can reveal additional vulnerabilities or weaknesses that can be exploited for decryption. We have chosen a simple ransomware, so we can easily point out the important details about how RSA encryption is integrated by ransomware creators and why decryption tends to be difficult or impossible.

ESXiArgs is a ransomware used to encrypt VM volumes after killing them if they are running [16].

This is a relatively simple ransomware where the author left debug symbols in, which may have been intentional - we know exactly how it operates, but we still can't fix it.

The ransomware finds and uses existing OpenSSL library functions on the PC, including the library's object types. The encrypt binary contained within creates a symmetrical key, then uses asymmetric RSA encryption with a public key, and adds the key to the end of the file.

The decrypt binary which takes the key from the end of the file and decrypts it with a private key is also present. The fundamental problem is that the private key is never present on the victim's computer in any form unless the attacker gives it to them, because RSA encryption with a public key was used.

## Why is there no legitimate RSA decryption hack

The creation of a private and a public key begins with two prime numbers: p and q. Even if the modulus number n (which is equal to p * q and its bit length is the length of the key) is public, we don’t have an efficient way of getting its prime components p and q back. If we managed to figure this math out (which nobody in the world has managed to), then RSA would be dead [17].

The only other value than n, p and q used in RSA is e, which is mostly common from around 4 often used numbers, usually `e = 65537`.

For RSA-2048 the number n should take up 2048/8 = 256 bytes and for RSA-4096 4096/8 = 512 bytes. Very small n can easily be factored back into primes p and q, but these 256 byte and 512 byte long numbers are just too large [18].

Perhaps instead of factorization we could take a different approach: How many prime number multiplications that fit into 256 bytes are there? If the length of n is 256 bytes and it is composed of the multiplication of two prime numbers, then there has to be a fairly limited set of prime number multiplication combinations that lead up to 256 bytes. In order to figure this out we have to look at the number of all computed prime numbers up to 256 bytes divided by 3 (considering that 3 is the only lowest prime number other than 1 and we have to multiply by this second number with the result fitting the 256 bytes) and then count all multiplications of two primes fitting 256 bytes.

How many multiplications of primes are there in 256 bytes? Are there any rainbow tables? "None of that applies to RSA, or any encryption, because encryption is reversible, unlike hashing which is mimicable. In encryption, you want to actually find the data that was encrypted, not something that encrypts to a similar ciphertext. For example, if the original message was 'Attack at dawn', you want to find that exact message, not 'Xyasjk la eopq'" [19].

Another problem can be 0 and 1 input into encryption resulting in same 0 and 1 output due to multiplication of 0 by itself and 1 by itself not increasing the number at all, however even if this vulnerability was present (input not being securely mapped onto the RSA functions) we can't expect to get any information from just two specific characters, which on the ASCII table (a simpler case where it could be used) don't even correspond to alphanumeric characters.

## Actually, there could be a way...

There was a capture-the-flag challenge years back called rhme2, where the vulnerability is that the RSA generation shared prime numbers of either p or q between different public keys and we as attackers know those public keys. This way we could crack RSA by simply getting the greatest common divisor between both n [17].

Another case is when p and q are close to each other, in which case we can brute force the other value by continuously adding 1 [18]...

Perhaps these reasons are why accessing the functions behind RSA algorithm (and other encryption algorithms) in Python cryptography library is under the “hazmat” (hazardous material) class, has a large red warning in documentation and should be left to the wrappers provided by the same library, that developers normally use.
  
Considering, that ransomware code we know about loads the OpenSSL library instead of doing the RSA encryption in a possibly exploit-prone way, we are out of luck. If we found ransomware, which tries to implement RSA on their own or uses a very outdated library, then we could leverage some known exploits; however it’s still true, that the RSA algorithm itself, if implemented and used properly (like in the OpenSSL implementation), is unhackable.

A good question is how OpenSSL combats the issue of p and q being close to each other or p or q being reused between different n. Perhaps randomization by mouse movement or similar means between runs generates different-enough results? Another question is if OpenSSL drops low n values which are also easy to factorize back into two prime multipliers.

If you follow OpenSSL, the last time it released a Critical patch was for HeartBleed (CVE-2014–0160) in 2014. This vulnerability exposed sensitive information, such as secrets and private keys, that were SSL/TLS protected. In 2022 there were two buffer overrun CVEs CVE-2022–3786 and CVE-2022–3602. Even the most recent CVE mentioned on OpenSSL website [31] (CVE-2024-9143) from October 2024 has a remote code execution possibility, however all of these are related to certificates, not private/public keys and not implementation of encryption itself. In 2023 there was CVE-2023-6129, where during encryption of a very specific uncommon algorithm on PowerPC architecture certain registers would get corrupted, another vulnerability CVE-2023-5363 involved incorrect key processing due to loss of uniqueness [31]. Assume we would find an exploit like the last one relating to AES or RSA and it would be triggerable on major operating systems (Windows, Linux, macOS, Android, ...) or platforms (x64 or ARM), then we would definitely hear about it, yet the last time we truly heard about something serious with OpenSSL was indeed Heartbleed in 2014.

## Brute-force time estimates

Looking at the time a brute force decryption would take, different sources give different estimates. If 512-bit RSA takes `C` time to be brute forced, then 1024-bit would take `C * 10^8` and 2048-bit `C * 10^17` [20]. 

![RSA factorization and brute force time](https://i.sstatic.net/4nkJr.png)

- Using verified estimates from cryptographic research [21]:
  - RSA-1024: ~3.25 years on standard hardware
  - RSA-2048: ~14 billion years on standard hardware
- Scientifically proven timelines [32]:
  - Life on Earth: 3.7 billion years ago
  - Earth's formation: 4.54 billion years ago  
  - Solar system formation: 4.6 billion years ago
  - Universe age: 13.78 billion years

Research shows significant differences in brute force times between RSA key lengths. According to DigiCert [33], brute forcing RSA-2048 would take over 14 billion years on a standard computer, which is 4.3 billion times (2^32) longer than RSA-1024's estimated 3.25 years. This clearly demonstrates why RSA-1024 should not be used while RSA-2048 brute force attempts would (without accounting for future improvements in technology) take longer than the current age of the universe.

Quantum computing estimates vary widely. One study [22] suggests RSA-1024 could be broken in 14 days using 2 billion ions over 103.5m2, while RSA-2048 might require 500 million ions and 10 days. However, these figures are highly theoretical and depend on many variables including error rates, qubit gate times, and other quantum mechanical factors. For our practical purposes of analyzing ransomware decryption, we'll focus on currently available classical computing resources.

There are two relevant algorithms: Shor's and Grover's. Shor's algorithm can be used for factorizing, but only factorizing. Grover's algorithm can be used for black-box queries. Advantage provided by a quantum computer over a regular personal computer is `O(sqrt(N))` complexity instead of `O(N)` complexity (number of trials). As for memory `log(K)` amount of qubits is required for `K` being the number of possible keys [20].

For quantum computing there is a python library called qiskit with Shor algorithm and the brute-force implementation can be done in 10 lines of code on IBM quantum computers [23]. These quantum computers can be rented for free for up to 10 minutes per month with at least 100 qubits with better plans available for educational institutions or researchers, however this is very limiting for RSA brute force, which requires thousands of qubits and definitely a very long compute time.

Sensational articles are also common such as the one that recently popped up on my Reddit feed: "RSA cracked by Chinese scientists" except it's only RSA-256 [24], for which the length of n is 256/8 = 32 bytes. As we already mentioned, the standard widely used RSA is 2048 or 4096. As we have established, you don't even need a quantum computer or a ton of time to crack RSA-256 in this day and age.

Let's ignore brute forcing math for a second, RSA actually takes a long time even if we only look at standard encryption itself:

![RSA encryption time by file size](https://www.researchgate.net/publication/307570334/figure/fig1/AS:401795126972417@1472806831786/Encryption-Time-for-RSA-and-A-RSA-Cryptosystems.png)

This means, that if RSA can take 25 seconds to encrypt a 10 MB sized file  [25], many ransomware strains opt to use 128-bit AES in combination with RSA, which is only used on the AES key.

---

# AES

As we have seen in the ESXiArgs ransomware example, hybrid RSA+AES encryption can be done by encrypting AES key with RSA instead of actual file contents and appending it to the fully AES encrypted file [26]. This dramatically lowers the compute time while still retaining some benefits of assymetric RSA encryption [27] and it usually works as follows:

1. A random AES key is generated to encrypt the target file or files
2. The AES key is encrypted using a public RSA key, which can often be found somewhere on the compromised machine
3. The encrypted files are stored with the RSA-encrypted AES key appended
4. The private RSA key is needed for decryption to first recover the AES key

What if we just cut off the encrypted key from the file contents and brute-forced the 128-bit AES?

![AES brute-force requirements](https://i.sstatic.net/L6374.png)

Even though it is sometimes claimed that 128-bit AES provides equivalent security to 3072-bit RSA [NIST SP 800-57], such comparison is not accurate since they use fundamentally different mathematical approaches. Quantum computing resource estimates also vary significantly between papers and implementation approaches. Claims about qubit requirements must be treated cautiously without authoritative sources. What we can say with more confidence is that both AES-128 and RSA-3072 are currently considered cryptographically secure against classical computers.

Reason why AES is very powerful is because the procedure done during each round of encryption causes the output to look completely incomprehensible unless you have the key.

Some working brute force methods involve cache timing attacks and side channel attacks, however these are largely a thing of the past, because modern processors come equipped with ability to do AES encryption on hardware level.

"It is not important to consider the expected number of AES operations for brute-force search of the AES key (2^127 for AES-128, 2^255 for AES-256) because that's not the best (nor a credible) attack strategy." [28]

So, can quantum computers break AES-128?

No [29] [30]. NIST estimates that a quantum computer breaking RSA-2048 in a matter of hours could be built by 2030 for about a billion dollars. This means that NIST estimates early quantum computers to have a clock rate of a few MHz. Such a quantum computer (a single 20 MHz quantum core) running Grover’s algorithm would need 1011 years (a hundred billion years) to break AES-128. Even a cluster of 109 quantum cores (the world's largest public classical supercomputer has 107 cores) with a clock rate of 2 THz would need 106 years (a million years) to break AES-128.
Considering all this, Grover’s algorithm does not pose any apparent threat to symmetric cryptography. Some years ago, there was a common conception that Grover’s algorithm required symmetric key sizes to be doubled – requiring use of AES-256 instead of AES-128. This is today considered a misconception – NIST, for example, now states that AES-128 will likely remain secure for decades to come, despite Grover’s algorithm [29] [30].

In fact, one of the security levels in the NIST PQC standardization is equivalent to that of AES-128. This means that NIST thinks it is relevant to standardize parameters for PQC that are as strong under quantum attacks as AES-128. There could, of course, be other reasons why a longer key is needed, such as compliance, and using a longer key only has a marginal effect on performance [29] [30].

---

# Planning reverse engineering

With what we learned so far about RSA and AES, the only way to decrypt related ransomware is to either discover a flaw in its code or capture the key in memory.

Further analyzing encryption techniques involves using tools like IDA Pro for reverse-engineering the ransomware's binary and Wireshark for capturing network traffic to understand the communication patterns and potential data exfiltration methods. Findings from these can reveal the specific encryption algorithms used, key sizes, and the overall encryption process. We need to understand these details to attempt decryption or develop mitigation strategies.

## Stage 1: Setup procedure

First let's carefully plan how to execute the reverse-engineering process of dangerous ransomware without compromising the safety of host device and nearby devices sharing the same network connection.

Usage of a different host operating system than one the ransomware was intended for is a good idea in terms of precaution. I will be using a macOS host machine with VMware Fusion software installed for virtualization of guest machines. VMware Fusion has side channel mitigations baked in. The setup procedure is as follows:

- install a windows vm
- DISABLE all folder sharing including drag and drop, clipboard, bluetooth and USB with host OS to keep possible ransomware encryption fallout within VM
- try to find and enable any useful VM hardening features
- DON'T ever connect guest OS to wifi, only to mobile hotspot, so other hosts on same network won't get compromised
- DON'T allow guest OS access to the wifi adapter, only to our mobile hotspot connection over "ethernet"
- harden host firewall to not expose any service with file access like Telnet, HTTP, HTTPS, SMB and SSH
- have tooling installed: IDA, Wireshark, Python3, GNUwin32 CoreUtils, FreeFileSync (this can be done without internet exposure)
- test that tooling works
- setup WireShark to send packet capture to remote host if possible or save capture files to a place the ransomware is unlikely to touch (like `system32`)
- map folder hierarchy of C: drive using FreeFileSync or `find` to external database for later comparison of changed files (monitor changes by filesize, file creation and modification dates)
- create initial VM snapshot
- copy ransomware onto machine
- create secondary VM snapshot

## Stage 2: Debug procedure

- run ransomware in IDA Pro
- try to always add a break before encryption call
- if possible, replace encryption function with dummy data to nullify its functionality
- run the rest of ransomware
- explore network traffic using Wireshark
- explore modified files using FreeFileSync or `find`
- save and document findings, highlights and differences
- return to previous VM snapshots in case of failure due to encryption or to move onto the next ransomware

## Stage 3: Drawing conclusions

- gather all collected data in one place
- do additional research
- write down conclusions about findings

---

# Conclusion

Ransomware decryption is a complex challenge. Brute-forcing strong encryption like RSA-2048 and AES-128 is practically impossible with current technology. Exploiting implementation flaws or capturing keys in memory offer more realistic avenues.

# Literature

(1) HEIMDALSECURITY. 2022. *Ransomware Encryption Methods: How Hackers Lock Your Files and Data* [Online] [Visited on 2024-10-28]. Available from: https://heimdalsecurity.com/blog/ransomware-encryption-methods/

(2) NOMORERANSOM.org. *Decryption Tools* [Online] [Visited on 2024-10-28]. Available from: https://www.nomoreransom.org/en/decryption-tools.html

(3) BleepingComputer. 2013. *How to remove Locky ransomware and try to recover your files* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/3-3rW6ZiOvY

(4) MALPEDIA. *PyLocky* [Online] [Visited on 2024-10-28]. Available from: https://malpedia.caad.fkie.fraunhofer.de/details/win.pylocky

(5) BleepingComputer. 2016. *Decrypted: The New AutoLocky Ransomware Fails to Impersonate Locky* [Online] [Visited on 2024-10-28]. Available from: https://www.bleepingcomputer.com/news/security/decrypted-the-new-autolocky-ransomware-fails-to-impersonate-locky/

(6) NIST. *CVE-2017-0144* [Online] [Visited on 2024-10-28]. Available from: https://nvd.nist.gov/vuln/detail/cve-2017-0144

(7) BBC News. 2017. *Cyber-attack: Ransomware worm exploits vulnerability* [Online] [Visited on 2024-10-28]. Available from: https://www.bbc.com/news/world-europe-39907965

(8) ZDNet. 2014. *Registry hack enables continued updates for Windows XP* [Online] [Visited on 2024-10-28]. Available from: https://www.zdnet.com/article/registry-hack-enables-continued-updates-for-windows-xp/

(9) The Hacker News. 2018. *WannaCry Ransomware Attack Disrupts Operations at World's Largest Chip Maker TSMC*[Online] [Visited on 2024-10-28]. Available from: https://thehackernews.com/2018/08/tsmc-wannacry-ransomware-attack.html

(10) CyberPolicy. *Who is Lazarus? North Korea's Newest Cybercrime Collective* [Online] [Visited on 2024-10-28]. Available from: https://www.cyberpolicy.com/cybersecurity-education/who-is-lazarus-north-koreas-newest-cybercrime-collective

(11) BleepingComputer. 2014. *CryptoWall Ransomware Information* [Online] [Visited on 2024-10-28]. Available from: https://www.bleepingcomputer.com/virus-removal/cryptowall-ransomware-information

(12) BleepingComputer. 2015. *CryptoWall 4.0 Released With New Features Such as Encrypted File Names* [Online] [Visited on 2024-10-28]. Available from: https://www.bleepingcomputer.com/news/security/cryptowall-4-0-released-with-new-features-such-as-encrypted-file-names/

(13) Marcelo Pires. 2017. *CryptoWall 3.0 Ransomware* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/oFt3rhA1mqQ

(14) Marcelo Pires. 2017. *Cryptowall 4.0 Ransomware Removal Instructions.* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/ABN9L82TKFc

(15) Wikipedia. *RSA algorithm* [Online] [Visited on 2024-10-28]. Available from: https://simple.wikipedia.org/wiki/RSA_algorithm

(16) BleepingComputer. 2023. *ESXiArgs Ransomware Support Topic* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/DdVC1eVfZUI

(17) LiveOverflow. 2020. *Why RSA is so secure (simply explained)* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/sYCzu04ftaY

(18) Computerphile. 2017. *Cracking Enigma - Numberphile* [Online] [Visited on 2024-10-28]. Available from: https://youtu.be/-ShwJqAalOk

(19) Quora. *Why can't a public RSA key be used to generate a rainbow table to break encryption?* [Online] [Visited on 2024-10-28]. Available from: https://www.quora.com/Why-cant-a-public-RSA-key-be-used-to-generate-a-rainbow-table-to-break-encryption

(20) Stack Exchange. *Assuming a 1024qb quantum computer, how long to brute force 1024bit RSA (256bit sym)?* [Online] [Visited on 2024-10-28]. Available from: https://crypto.stackexchange.com/questions/9480/assuming-a-1024qb-quantum-computer-how-long-to-brute-force-1024bit-rsa-256bit

(21) NIST. 2019. *Security Strength of RSA in Relation to Factoring-Based Attacks* [Online] [Visited on 2024-10-28]. Available from: https://www.nist.gov/publications/security-strength-analysis-rsa

(22) Science. 2017. *Realization of a scalable Shor algorithm* [Online] [Visited on 2024-10-28]. Available from: https://www.science.org/doi/10.1126/sciadv.1601540

(23) IBM. *IBM Quantum Pricing* [Online] [Visited on 2024-10-28]. Available from: https://www.ibm.com/quantum/pricing

(24) Live Science. 2024. *Chinese scientists claim they broke RSA encryption with a quantum computer — but there's a catch* [Online] [Visited on 2024-10-28]. Available from: https://www.livescience.com/technology/computing/chinese-scientists-claim-they-broke-rsa-encryption-with-a-quantum-computer-but-theres-a-catch

(25) ResearchGate. *Encryption Time for RSA and A-RSA Cryptosystems* [Online] [Visited on 2024-10-28]. Available from: https://www.researchgate.net/figure/Encryption-Time-for-RSA-and-A-RSA-Cryptosystems_fig1_307570334

(26) arXiv. 2019. *A Study of Encryption Algorithms (RSA, DES, 3DES and AES) for Information Security* [Online] [Visited on 2024-10-28]. Available from: https://arxiv.org/abs/1903.11023

(27) ScienceDirect. 2021. *A Comparative Analysis of the Performance of Cryptographic Algorithms: DES, 3DES, AES, RSA and Blowfish* [Online] [Visited on 2024-10-28]. Available from: https://www.sciencedirect.com/science/article/pii/S221420962100001X

(28) Stack Exchange. *How many operations to brute-force AES?* [Online] [Visited on 2024-10-28]. Available from: https://crypto.stackexchange.com/a/63218

(29) Ericsson. 2017. *Post-quantum cryptography in mobile networks* [Online] [Visited on 2024-10-28]. Available from: https://www.ericsson.com/en/blog/2017/6/post-quantum-cryptography-in-mobile-networks

(30) Ericsson. 2017. *Ensuring security in mobile networks post-quantum* [Online] [Visited on 2024-10-28]. Available from: https://www.ericsson.com/en/reports-and-papers/ericsson-technology-review/articles/ensuring-security-in-mobile-networks-post-quantum

(31) OpenSSL. *Security Vulnerabilities* [Online] [Visited on 2024-10-28]. Available from: https://openssl-library.org/news/vulnerabilities/

(32) NASA Science. *Universe Facts* [Online] [Visited on 2024-10-28]. Available from: https://science.nasa.gov/universe/facts/

(33) DigiCert. *What is SSL Cryptography?* [Online] [Visited on 2024-10-28]. Available from: https://www.digicert.com/faq/cryptography/what-is-ssl-cryptography
