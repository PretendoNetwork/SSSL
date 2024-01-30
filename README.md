# SSSL - Hackless SSL bypass for the Wii U

On March 1, 2021 Nintendo released Wii U firmware version [5.5.5](https://wiiubrew.org/wiki/5.5.5). This update updated the Wii U's SSL verification. The exact purpose for this update is unknown, as nothing of significance was changed, and no other changes were made in this update. With the changes to SSL verification, Nintendo introduced a bug which allows for the forging of SSL certificates. These forged certificates will be seen as "Nintendo Signed" and, due to an existing bug with how the Wii U handles CA common names, will be accepted by all domains.

## The bugs
There are 2 bugs at play:

1. Normally a CA common name does not accept a single wildcard (\*) value. They must contain a hostname, and optionally one or many wildcards for subdomains. The Wii U will accept a single \* wildcard in place of a hostname, which allows the CA to be accepted as any domain. This bug has existed since before 5.5.5, but was not useful until now.
2. As of 5.5.5, CA's crafted in a specific way may take a newly introduced alternate path for verification. This allows for a CA's signature to not be verified correctly. Instead, the Wii U simply checks if the certificate was *issued* by a CA, but not necessarily *signed* by one. We have no idea why this change was made, as it does not benefit Nintendo at all. It almost feels intentional.

## Exploiting
Not any CA will work. There are 2 conditions for a CA which still need to be met even for a forged CA to be accepted:

1. The CA needs to be one which the Wii U would already accept. The signature is not validated in this case, so modifying an existing CA works.
2. The Wii U does not allow a Root CA in the cert chain. It will ignore any certs that have a matching subject and authority key.

The easiest way to exploit this bug is to use the Nintendo CA - G3 CA, and is what this script opts to do. This can be dumped from a Wii U's SSL certificates title at `/storage_mlc/sys/title/0005001b/10054000/content/scerts/CACERT_NINTENDO_CA_G3.der`. Changing the public key to a user-controlled key and changing the authority key identifier to anything else is all that is required. The resulting user-controlled private key and patched CA can be used to bypass SSL verification without any homebrew or CFW at all.

## The script
This script takes in a PEM encoded copy of Nintendo CA - G3 and does the above patches and exports the patched CA and private key.

- Install [NodeJS](https://nodejs.org/)
- `git clone git clone https://github.com/PretendoNetwork/SSSL`
- `cd SSSL`
- `npm i` (this only needs to be done once)
- Place `CACERT_NINTENDO_CA_G3.pem` in the same folder as this script
- `node patch`

## Credits
- Shutterbug for actually finding the new verification bug
- Jemma and Quarky for decompiling the updated SSL functions