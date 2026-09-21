# crypto

It's just me having some fun with cryptographic functions in C, oriented around hashing and asymetric encryption (so far). 

CMake is simple, maybe will get better in future. Built and developed on Linux Mint. Used gcc 13.3.0.

**Note**: I use *GMP* for large integers logic, but did not include it as external lib, just have it on my OS:
```sudo apt update && sudo apt install libgmp-dev -y```

The plan is:
- SHA-256 - NIST FIPS 180-4
- SHA-512 - NIST FIPS 180-4 
- RSA-2048 - RFC 8017 - this includes:
  - IFC Key Generation - NIST FIPS 186-5
  - HMAC_DRGB - SP 800-90A - omitting SP 800-90B/C shenanigans, just simply reading entropy input from `/dev/urandom`

The functions has been tested manually using official testing vectors. I have not yet created software tests for this. Maybe will do in some future.
