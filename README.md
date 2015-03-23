# GBCrypt
GBCrypt is a simple application used to encrypt and decrypt data.  

GBCrypt use AES 256-bit encryption combine Blowfish, data after decrypt will be recheck with SHA1 checksum for ensuring integrity.   

GBCrypt use RSA 4096-bit algorithm to encrypt key of AES and Blowfish. All of keys AES and Blowsfish will be embed to encrypted file. So, end user only keep RSA private key for decrypting and public key for encrypting.
