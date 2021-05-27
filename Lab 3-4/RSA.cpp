// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <assert.h>

int main(int argc, char *argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 3072);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        string plain = "RSA Encryption", cipher, recovered;

        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey);

        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)) // PK_EncryptorFilter
        );                                                          // StringSource

        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor d(privateKey);

        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)) // PK_EncryptorFilter
        );                                                             // StringSource

        assert(plain == recovered);
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

    return 0;
}
