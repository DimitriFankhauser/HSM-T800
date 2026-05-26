# Repo Info
The goal of this TUI is to make it simpler to deal with HSMs for people who know the basic concepts but don't know the entire [475 page documentation by heart](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/cs01/pkcs11-spec-v3.2-cs01.pdf). This project was built using [miekg/pkcs11](https://github.com/miekg/pkcs11) and [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11).

This project has been tested using [SoftHSMv2](https://github.com/softhsm/SoftHSMv2) and [Nitrokey HSM 2](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7)


## Functionality
- Import of PEM KeyPairs and Certificates
- Creation of (RSA 2048-3072-4096/ECC 256-384-521) KeyPairs
- Export of Public Keys
- Generation of Application.Properties and pkcs.cfg files for HSM-based TLS in [Quarkus](https://github.com/quarkusio/quarkus/pull/54326)
- creation of CSRs
