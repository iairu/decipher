# Ondrej Špánik 

**DEŠIFROVANIE RANSOMVÉRU**

December 2024 BIT@FIIT.STU  

---

## Intro
- Nie je to zastavenie, hacknutie, debugovanie
- Je to tvorba dešifrovacej metódy pre obnovu dát
  - Ako funguje ransomvér?
  - Ako dešifrovať algoritmus? Má zraniteľnosti?
  - Ako obísť celý proces a dešifrovať nedešifrovateľné?

---

## Reverzné inžinierstvo
- **Nástroje**: Unpacme, VM, IDA, Ghidra
- **Techniky**:
  - Dynamické importy (libky)
  - Postupný labeling
  - Synchronizácia pseudokódu
  - Dokumentácia pre Windows API

---

## WannaCry
- Vytvorí službu cez TaskScheduler, šifruje každý nový disk
- KillSwitch len ak funguje internet a daná doména
- Šírenie aj cez RDP, využíva SMB exploit EternalBlue
- Kombinácia RSA a AES

---

## Realita
- **90%+ ransomvéru** je kombinácia RSA a AES:
  - AES: rýchly :), symetrický :(
  - RSA: pomalý :(, asymetrický :)
  - Spolu: takmer nedešifrovateľné >_<

---

## Algoritmus
1. Strom súborov
2. Rekurzívne pre každý súbor:
   - Generovanie symetrického AES (treba správne typy!)
   - Zašifrovanie súboru pomocou AES
   - Zašifrovanie AES kľúča pomocou RSA
   - Pripojenie kľúča k súboru

---

## RSA
- **Princíp**:  
  - súčin veľkých prvočísel `p * q = n`
  - `n`: verejné (modulus)
  - `e`: väčšinou známa hodnota (verejný kľúč je dvojica `(e,n)`)
  - Ak poznáme `p` a `q`, môžeme vypočítať `d` (privátny kľúč je dvojica `(d,n)`)
  - Sila RSA: neschopnosť nájsť `d`, resp. faktorizovať `n` naspäť na `p` a `q` v ľudskom čase
    - 2024: RSA-2048 ideál v miliardách rokoch, RSA-1024 slabý a otázka mesiacov-rokov

---

## RSA Zraniteľnosti
- Identifikoval som nasledovné:
  - Zdieľané `p` alebo `q` medzi viacerými kľúčmi
  - Blízke `p` a `q`: brute force faktorizácia
  - Šifrovanie 0 alebo 1 má vždy rovnaký výstup
- Väčšina ransomvéru využíva OpenSSL (zraniteľnosti neplatia) :(
- Zostáva už len zachytenie privátneho kľúča (vzácne)

---

## Pamäťový dump (src/main.c)
- Zachytenie privátneho kľúča kým je v RAM
  - Ransomvér ukladá verejný kľúč `(e,n)` lokálne:
    - `n` (modulus) vieme
    - `e` vieme
  - Treba nájsť `p`, `q` ako prvočísla rovné `n`
  - Skúsiť kľúč
- Uloženie kľúča a dešifrovanie vlastným softvérom alebo ransomvérom
