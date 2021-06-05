//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;
// hex convert
#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
// File operation
#include <cryptopp/files.h>

int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct standrad curve from OID
    /* ECC curve */
    CryptoPP::OID oid= ASN1::secp384r1();
    /* Create a curve for ECDH*/ 
    CryptoPP::ECDH<ECP>::Domain ecdh(oid);
    CryptoPP::DL_GroupParameters_EC<ECP> curve256;
    curve256.Initialize(oid);
    /* Create key pairs private key d; public key Q=d.G*/
    CryptoPP::SecByteBlock privA(ecdh.PrivateKeyLength()), pubA(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(rng, privA, pubA);
    CryptoPP::SecByteBlock privB(ecdh.PrivateKeyLength()), pubB(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(rng, privB, pubB);
    // Read the private key A
    CryptoPP::Integer prkeyA(privA, sizeof(privA));
    cout << "private key prkey A=" << prkeyA <<endl;
    // Read the public key point of A
    ECP::Point G=ecdh.GetGenerator();
    ECP::Point QA=curve256.GetCurve().Multiply(prkeyA,G);
    cout << "Public key QAx=" << QA.x << endl;
    cout << "Public key QAy=" << QA.y << endl;

    // Read the private key B
    CryptoPP::Integer prkeyB(privB, sizeof(privB));
    cout << "private key prkey B=" << prkeyB <<endl;
    // Read the public key point of B
    ECP::Point QB=curve256.GetCurve().Multiply(prkeyB,G);
    cout << "Public key QBx=" << QB.x << endl;
    cout << "Public key QBy=" << QB.y << endl;

    // Session  key A
    ECP::Point SKA=curve256.GetCurve().Multiply(prkeyA, QB);
    // Session  key B
    ECP::Point SKB=curve256.GetCurve().Multiply(prkeyB, QA);

    cout << "SKAx=" << SKA.x << endl;
    cout << "SKBx=" << SKB.x << endl;
    cout << "SKAy=" << SKA.y << endl;
    cout << "SKBy=" << SKB.y << endl;
    // Session key H(SKA||....) 

}