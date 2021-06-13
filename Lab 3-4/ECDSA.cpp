#include <iostream>
#include <string>
using namespace std;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "helper.cpp"
using helper::integer_to_wstring;
using helper::ReadPlaintextFromFile;
using helper::SetupVietnameseSupport;
using helper::string_to_wstring;
using helper::wstring_to_string;

// Generate the private key from a given curve via OID
bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    AutoSeededRandomPool prng;
    key.Initialize(prng, oid);
    return key.Validate(prng, 3);
}

// Generate the public key derived from a given private key
bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
    AutoSeededRandomPool prng;
    privateKey.MakePublicKey(publicKey);
    return publicKey.Validate(prng, 3);
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params)
{
    wcout << endl;
    wcout << "Modulus:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;

    wcout << "Coefficient A:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetA()) << endl;

    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetB()) << endl;

    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl;
    wcout << " Y: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;

    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;

    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

// Print the private exponent to console
void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl;
}

// Print the public element to console
void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key)
{
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl;
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

// Save the private key (in binary) to file
void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

// Save the public key (in binary) to file
void SavePublicKey(const string &filename, const ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

// Load the private key from file
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

// Load the public key from file
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

// Sign the message using the private key and store the signature to "signature"
bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &key, const string &message, string &signature)
{
    AutoSeededRandomPool prng;
    signature.erase();
    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA256>::Signer(key),
                                  new StringSink(signature)) // SignerFilter
    );                                                       // StringSource
    return !signature.empty();
}

// Verify the signature of the message using the public key
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &key, const string &message, const string &signature)
{
    bool result = false;
    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA256>::Verifier(key),
                     new ArraySink((CryptoPP::byte *)&result, sizeof(result))) // SignatureVerificationFilter
    );
    return result;
}

int main(int argc, char *argv[])
{
    SetupVietnameseSupport();

    // Scratch result
    bool result = false;

    // Private and Public keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;

    // Generate Keys
    if (!GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), privateKey))
    {
        wcout << "Cannot generate the private key!" << endl;
        exit(1);
    }

    if (!GeneratePublicKey(privateKey, publicKey))
    {
        wcout << "Cannot generate the public key!" << endl;
        exit(1);
    }

    // Print Domain Parameters and Keys
    PrintDomainParameters(publicKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);

    // Save key in PKCS#9 and X.509 format
    SavePrivateKey(".\\Lab 3-4\\ec.private.key", privateKey);
    SavePublicKey(".\\Lab 3-4\\ec.public.key", publicKey);

    // Load key in PKCS#9 and X.509 format
    LoadPrivateKey(".\\Lab 3-4\\ec.private.key", privateKey);
    LoadPublicKey(".\\Lab 3-4\\ec.public.key", publicKey);

    // Print Domain Parameters and Keys
    PrintDomainParameters(publicKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);

    // Read message from file
    string message = ReadPlaintextFromFile(".\\Lab 3-4\\message.txt");

    // Sign and Verify a message
    string signature;

    if (!SignMessage(privateKey, message, signature))
    {
        cout << "Failed to sign the message!" << endl;
    }
    else if (!VerifyMessage(publicKey, message, signature))
    {
        cout << "Failed to verify the message!" << endl;
    }
    else
    {
        cout << "All is good!" << endl;
    }

    return 0;
}
