# FRODO SHAKE 640 KEM Implementation

Welcome to the FRODO SHAKE 640 Key Encapsulation Mechanism (KEM) repository!

This repository contains two variations of the code implementing the FRODO SHAKE 640 KEM: CCA secure and CPA secure.(2 brances in this repository).

## Variations in the Repository

### CPA Secure
The code under the "CPA secure" directory represents a variant of the FRODO SHAKE 640 KEM that's susceptible to chosen plaintext attacks (CPA). This implementation intentionally allows individuals to explore and understand attack vectors for educational purposes.

### CCA Secure
The "CCA secure" code, on the other hand, represents the original FRODO SHAKE 640 KEM with heightened security measures, including more complex randomization techniques and safeguards against chosen ciphertext attacks (CCA).

## Project Purpose
This project serves as a learning resource developed as part of the ENPM 657 Applied Cryptography course. Its primary aim is to facilitate an environment where students can explore, analyze and understand the vulnerabilities associated with different security schemes in cryptographic systems.

## Usage
### Rest API Server
We've designed this implementation as a REST API server enabling individuals to interact with and test the CPA secure variant. Feel free to explore, attack and learn from this setup.

## Source Repository
This repository is based on the original work from [Microsoft's PQCrypto-LWEKE](https://github.com/Microsoft/PQCrypto-LWEKE) repository.

## Contribution and Support
Contributions and feedback are greatly appreciated! If you encounter issues or have suggestions or want to contribute enhancements please feel free to create issues or pull requests.

Happy learning and exploring the world of applied cryptography!
