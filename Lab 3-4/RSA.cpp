// Sample.cpp

#include "stdafx.h"

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 1024 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain="RSA Encryption", cipher, recovered;

        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e( publicKey );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource

        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor d( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

