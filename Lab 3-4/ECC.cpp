//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

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
using CryptoPP::DL_FixedBasePrecomputation;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::ECIES;
using CryptoPP::ECP; // Prime field p
using CryptoPP::ECPPoint;

#include <cryptopp/pubkey.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> //
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

int main(int argc, char *argv[])
{
    AutoSeededRandomPool rng;

    // Define curve's parameters
    // Modulus p
    Integer p("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    // Coefiction a
    Integer a("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    // Coefiction b
    Integer b("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

    // a mod p
    a %= p;
    // b mod p
    b %= p;

    // CREATE A CURVE
    CryptoPP::ECP eqcurve256r1(p, a, b);

    /* subgroup <G> on curve */
    // x, y: Base Point G
    Integer x("0x046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    Integer y("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    // Creat point G
    ECP::Point G(x, y);
    // Order n of group <G>
    Integer n("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    // Cofactors
    Integer h("0x1");

    /* Set ECC parameters */
    CryptoPP::DL_GroupParameters_EC<ECP> curve256(eqcurve256r1, G, n, h);

    /* Curve parameters*/
    cout << "Group order n = " << curve256.GetGroupOrder() << endl;
    cout << "Cofactor h = " << curve256.GetCofactor() << endl;
    cout << "Coefficient a = " << eqcurve256r1.GetA() << endl;
    cout << "Coefficient b = " << eqcurve256r1.GetB() << endl;
    cout << "Gx = " << G.x << endl;
    cout << "Gy = " << G.y << endl;
}
