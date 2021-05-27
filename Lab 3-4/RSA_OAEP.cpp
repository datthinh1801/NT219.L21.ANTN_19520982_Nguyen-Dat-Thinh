// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
/* Convert to hex */ 
#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <assert.h>

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;
        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 3072 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain="Thuc hanh buoi 3", cipher, recovered;
        cout << "Plaintext: " << plain << endl;

        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e( publicKey ); // RSAES_PKCS1v15_Decryptor

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        string encoded;
        encoded.clear();
        StringSource(cipher, true, 
        new HexEncoder(new StringSink(encoded)) );
        cout << "Ciphertext: " << encoded << endl;
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
        cout << "Recover text:" << recovered << endl;
        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

