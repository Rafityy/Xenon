#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include "Parser.h"
#include "Package.h"

#define KEYSIZE             32
#define IVSIZE              16
#define AES_BLOCK_SIZE      16
#define SHA256_HASH_SIZE    32
#define UUID_SIZE           36


BOOL CryptoMythicEncryptPackage(PPackage package);
BOOL CryptoMythicDecryptParser(PPARSER parser);

#endif