#include <iostream>
#include <string>
#include <fstream>
using namespace std;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

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

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "helper.cpp"
using helper::integer_to_wstring;
using helper::ReadPlaintextFromFile;
using helper::SetupVietnameseSupport;
using helper::string_to_wstring;
using helper::wstring_to_string;

#define N_ITER 10000

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

void ReadSignatureFromFile(string filename, string &signature)
{
    ifstream fin(filename);
    if (fin.is_open())
    {
        string line;
        while (fin.good())
        {
            getline(fin, line);
            signature += line;
        }
        fin.close();
    }
    else
    {
        wcout << "Cannot open file " << string_to_wstring(filename) << "!" << endl;
        exit(1);
    }
}

void PrettyPrint(string str)
{
    // Convert byte string to a hex wstring,
    // and print to console.
    string encoded_string;
    StringSource(str, true,
                 new HexEncoder(
                     new StringSink(encoded_string)));
    wstring wstr = string_to_wstring(encoded_string);
    wcout << wstr << endl;
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
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl;
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void PrintKeys(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
    PrintDomainParameters(privateKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);
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

string SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const string &message)
{
    AutoSeededRandomPool prng;
    string signature;
    signature.erase();

    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA256>::Signer(privateKey),
                                  new StringSink(signature)));
    return signature;
}

// Sign the message using the private key and store the signature to "signature"
void SignMessageSetup(string privatekey_filename, string message_filename, string &signature)
{

    // Load private key from file
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    LoadPrivateKey(privatekey_filename, privateKey);

    // Read message from file
    string message = ReadPlaintextFromFile(message_filename);

    double etime = 0;

    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        signature = SignMessage(privateKey, message);
        if (signature.empty())
        {
            wcout << "Failed to sign message!" << endl;
            exit(1);
        }
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }

    PrintDomainParameters(privateKey);
    PrintPrivateKey(privateKey);
    wcout << "Signature: ";
    PrettyPrint(signature);
    wcout << "Average signing time: " << 1000 * etime / N_ITER << " ms." << endl;
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &publicKey, const string &message, const string &signature)
{
    // Verify message using the above public key
    bool result = false;
    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA256>::Verifier(publicKey),
                     new ArraySink((CryptoPP::byte *)&result, sizeof(result))));
    return result;
}

// Verify the signature of the message using the public key
void VerifyMessageSetup(string publickey_filename, string message_filename, string signature_filename)
{
    // Load public key from file
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    LoadPublicKey(publickey_filename, publicKey);

    string signature;
    ReadSignatureFromFile(signature_filename, signature);

    // Read message from file
    string message = ReadPlaintextFromFile(message_filename);

    double etime = 0;
    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        if (!VerifyMessage(publicKey, message, signature))
        {
            wcout << "Failed to verify message!" << endl;
            exit(1);
        }
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }

    PrintDomainParameters(publicKey);
    PrintPublicKey(publicKey);
    wcout << "Signature: ";
    PrettyPrint(signature);
    wcout << "Average verifying time: " << 1000 * etime / N_ITER << " ms." << endl;
}

// Generate private key and public key, then write them to files
bool GenerateKeyPair(const OID &oid, string privateKey_filename, string publicKey_filename)
{
    // Private and Public keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;

    if (!GeneratePrivateKey(oid, privateKey) || !GeneratePublicKey(privateKey, publicKey))
    {
        return false;
    }

    PrintKeys(privateKey, publicKey);

    // Save the key pair to files
    SavePrivateKey(privateKey_filename, privateKey);
    SavePublicKey(publicKey_filename, publicKey);
    return true;
}

void WriteSignatureToFile(string filename, const string &signature)
{
    ofstream fout(filename);
    if (fout.is_open())
    {
        fout << signature;
        fout.close();
    }
    else
    {
        wcout << "Cannot open file " << string_to_wstring(filename) << "!" << endl;
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    SetupVietnameseSupport();
    string sep;
#ifdef _WIN32
    sep = '\\';
#elif __linux__
    sep = '/';
#endif

    wcout << "What do you want to do?" << endl;
    wcout << "[1] Generate keys and write them to files." << endl;
    wcout << "[2] Sign a message from message.txt." << endl;
    wcout << "[3] Verify the signature." << endl;
    wcout << "> ";

    int option;
    try
    {
        wcin >> option;
    }
    catch (exception e)
    {
        wcout << "Exception on selection: " << e.what() << endl;
        exit(1);
    }

    string publickey_filename = "." + sep + "Lab 3-4" + sep + "ec.public.key";
    string privatekey_filename = "." + sep + "Lab 3-4" + sep + "ec.private.key";
    string message_filename = "." + sep + "Lab 3-4" + sep + "message.txt";
    string signature_filename = "." + sep + "Lab 3-4" + sep + "signature.txt";
    string signature;

    switch (option)
    {
    case 1:
        if (!GenerateKeyPair(CryptoPP::ASN1::secp256r1(), privatekey_filename, publickey_filename))
        {
            wcout << "Failed to generate key pair!" << endl;
            exit(1);
        }
        else
        {
            wcout << "Keys are written to " << string_to_wstring(privatekey_filename) << " and " << string_to_wstring(publickey_filename);
        }
        break;
    case 2:
        SignMessageSetup(privatekey_filename, message_filename, signature);
        WriteSignatureToFile(signature_filename, signature);
        wcout << "Sign the message successfully!" << endl;
        break;
    case 3:
        VerifyMessageSetup(publickey_filename, message_filename, signature_filename);
        wcout << "Verify the message successfully!" << endl;
        break;
    default:
        wcout << "Invalid option!" << endl;
        exit(1);
    }

    return 0;
}
