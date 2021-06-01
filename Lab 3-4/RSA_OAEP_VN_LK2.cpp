// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

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

#include <cryptopp/queue.h> // using for load functions
using CryptoPP::ByteQueue;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation; // using for load function
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/nbtheory.h"

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <assert.h>
#include "helper.cpp"

string RSA_Encrypt(AutoSeededRandomPool &rng, const RSA::PublicKey &rsaPublicKey, const string &plaintext)
{
    string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);
    StringSource(plaintext, true,
                 new PK_EncryptorFilter(rng, encryptor,
                                        new StringSink(ciphertext)));
    return ciphertext;
}

string RSA_Decrypt(AutoSeededRandomPool &rng, const RSA::PrivateKey &rsaPrivateKey, const string &ciphertext)
{
    string recovered_text;
    RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
    StringSource(ciphertext, true,
                 new PK_DecryptorFilter(rng, decryptor,
                                        new StringSink(recovered_text)));
    return recovered_text;
}

void PrettyPrint(string str)
{
    string encoded;
    encoded.clear();
    StringSource(str, true,
                 new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded);
}

string DecodeCiphertext(const wstring &wciphertext)
{
    string ciphertext;
    StringSource(wstring_to_string(wciphertext), true,
                 new HexDecoder(new StringSink(ciphertext)));
    return ciphertext;
}

void GenerateKeysRandomly(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey, int key_size)
{
    AutoSeededRandomPool rng;
    rsaPrivateKey.GenerateRandomWithKeySize(rng, key_size);
    rsaPublicKey = RSA::PublicKey(rsaPrivateKey);
}

void LoadKeysFromFiles(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
    try
    {
        AutoSeededRandomPool rng;
#ifdef _WIN32
        LoadPublicKey(".\\Lab 3-4\\rsa-public.key", rsaPublicKey);
        LoadPrivateKey(".\\Lab 3-4\\rsa-private.key", rsaPrivateKey);
#elif __linux__
        LoadPublicKey("./Lab 3-4/rsa-public.key", rsaPublicKey);
        LoadPrivateKey("./Lab 3-4/rsa-private.key", rsaPrivateKey);
#endif

        if (!rsaPrivateKey.Validate(rng, 3))
        {
            throw runtime_error("RSA private key validation failed.");
        }
        if (!rsaPublicKey.Validate(rng, 3))
        {
            throw runtime_error("RSA public key validation failed.");
        }
    }
    catch (CryptoPP::Exception &e)
    {
        wcout << "An exception occured while loading keys from files." << endl;
        wcout << e.what() << endl;
        exit(1);
    }
}

void GetKeyFromConsole(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
    wstring wstr_prime_p, wstr_prime_q, wstr_private_exp, wstr_public_exp;
    wcout << "##### Private key #####" << endl;

    // Get modulo n
    CryptoPP::Integer n = ReadIntegerFromConsole(L"Modulo n");
    rsaPrivateKey.SetModulus(n);

    // Get prime p
    CryptoPP::Integer p = ReadIntegerFromConsole(L"Prime p");
    rsaPrivateKey.SetPrime1(p);

    // Get prime q
    CryptoPP::Integer q = ReadIntegerFromConsole(L"Prime q");
    rsaPrivateKey.SetPrime2(q);

    // Get public exponential
    CryptoPP::Integer e = ReadIntegerFromConsole(L"Public exponential e");
    rsaPrivateKey.SetPublicExponent(e);

    // Get private exponential
    CryptoPP::Integer d = ReadIntegerFromConsole(L"Private exponential d");
    rsaPrivateKey.SetPrivateExponent(d);

    // https://stackoverflow.com/questions/23878893/why-does-this-throw-cryptomaterial-this-object-contains-invalid-values-in-c
    rsaPrivateKey.SetModPrime1PrivateExponent(d % (p - 1));
    rsaPrivateKey.SetModPrime2PrivateExponent(d % (q - 1));
    rsaPrivateKey.SetMultiplicativeInverseOfPrime2ModPrime1(q.InverseMod(p));
    // rsaPrivateKey.SetPublicExponent(d.InverseMod((p - 1) * (q - 1)));

    // Generate public key from the given private key
    rsaPublicKey = RSA::PublicKey(rsaPrivateKey);
}

int main(int argc, char *argv[])
{
    try
    {
        SetupVietnameseSupport();

        // Generate keys
        AutoSeededRandomPool rng;

        // Generate keys
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;

        GetKeyFromConsole(privateKey, publicKey);
        // GenerateKeysRandomly(privateKey, publicKey, 3072);
        PrintKeys(privateKey, publicKey);
        wcout << endl;
        ////////////////////////////////////////////////

        string plain;
        wstring wplain;

        wcout << "Input Plaintext: ";
        fflush(stdin);
        getline(wcin, wplain);
        plain = wstring_to_string(wplain);

        //////////////////////////////////////////////t/

        // Encryption
        string ciphertext;
        ciphertext = RSA_Encrypt(rng, publicKey, plain);

        wcout << "Ciphertext: ";
        PrettyPrint(ciphertext);
        wcout << endl;

        ////////////////////////////////////////////////

        // Decryption
        wcout << endl;
        string ciphertext_to_decrypt;
        wstring wciphertext_to_decrypt;

        wcout << "Ciphertext to decrypt: ";
        fflush(stdin);
        getline(wcin, wciphertext_to_decrypt);
        if (wciphertext_to_decrypt[wciphertext_to_decrypt.size() - 1] != L'H')
        {
            wciphertext_to_decrypt += L"H";
        }
        ciphertext_to_decrypt = DecodeCiphertext(wciphertext_to_decrypt);

        /* Decrypt */
        string recovered_text = RSA_Decrypt(rng, privateKey, ciphertext_to_decrypt);
        wcout << "Recover text: " << string_to_wstring(recovered_text) << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
