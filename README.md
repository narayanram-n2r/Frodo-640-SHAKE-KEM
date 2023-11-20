# FRODO SHAKE 640 KEM Implementation (Python)

Welcome to the FRODO SHAKE 640 Key Encapsulation Mechanism (KEM) Python implementation repository!

This repository hosts Python implementations of FRODO KEM, specifically the FRODO-640 variant using SHAKE. FRODO KEM is an IND-CCA secure key encapsulation protocol based on the Learning with Errors (LWE) problem. This library implements FRODOKEM, conjectured to be secure against quantum computer attacks.

## About FRODO KEM

FRODO KEM utilizes the Learning with Errors problem and is designed to be secure against quantum attacks. It offers two variants:

- **Standard FrodoKEM:** Suitable for scenarios involving a large number of ciphertexts encrypted to a single public key.
- **Standard FrodoKEM with additional countermeasures:** Includes enhancements safeguarding against certain multi-ciphertext attacks.

This implementation specifically focuses on the FRODO-640 variant using the SHAKE function, providing post-quantum security comparable to AES128.

## Variations in the Repository

### CPA Secure and CCA Secure

- **CPA Secure Variant:** The "CPA secure" directory houses an intentionally vulnerable variant susceptible to chosen plaintext attacks (CPA). It's designed for educational purposes, allowing individuals to understand and explore attack vectors.
  
- **CCA Secure Variant:** The "CCA secure" directory contains the original FRODO SHAKE 640 KEM with heightened security measures, including complex randomization techniques and protection against chosen ciphertext attacks (CCA).

## Usage

This Python-based implementation serves as a REST API server, enabling communication with clients in various programming languages. The server itself is implemented using Python, while clients can communicate in a language of their choice.

## Supported Platforms

The FRODO KEM library is versatile, supporting various platforms including x64, x86, ARM, PowerPC, and s390x processors running Windows, Linux, or macOS. It accommodates both little-endian and big-endian formats, tested with Microsoft Visual Studio, GNU GCC, and clang.

## References

- [FrodoKEM: Learning With Errors Key Encapsulation - NIST Post-Quantum Standardization Project (2021-2023)](https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8309-draft.pdf)
- [Frodo: Take off the ring! Practical, quantum-secure key exchange from LWE - ACM CCS 2016](https://eprint.iacr.org/2016/659.pdf)
- [FrodoKEM: Learning With Errors Key Encapsulation - Preliminary Draft Standards (2023)](https://www.math.uni-frankfurt.de/~dmst/Stebila/FrodoKEM-2023.pdf)

## Acknowledgment

This Python implementation is based on the FrodoKEM team's work in collaboration with Microsoft Research for experimentation purposes.

Feel free to contribute, explore, and learn more about the world of applied cryptography with FRODO KEM!
