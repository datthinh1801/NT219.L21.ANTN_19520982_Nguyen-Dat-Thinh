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
    // Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);

    // User Defined Domain Parameters for curve y^2 =x^3 + ax +b
    // Modulus p
    Integer p("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    // Coefiction a
    Integer a("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    // Coefiction b
    Integer b("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    /* create a curve*/
    a %= p;
    b %= p; // a mod p, b mod p
    CryptoPP::ECP eqcurve256(p, a, b);
    /* subgroup <G> on curve */
    // x, y: Base Point G
    Integer x("0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    Integer y("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    // Creat point G
    ECP::Point G(x, y);
    // Oder n of group <G>
    Integer n("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    //Cofactors
    Integer h("0x1");
    /* Set ECC parameters */
    CryptoPP::DL_GroupParameters_EC<ECP> curve256(eqcurve256, G, n, h);
    /* Curve parameters*/
    cout << "Group order n=" << curve256.GetGroupOrder() << endl;
    cout << "Cofactor h=" << curve256.GetCofactor() << endl;
    cout << "Coefficient a=" << eqcurve256.GetA() << endl;
    cout << "Coefficient b=" << eqcurve256.GetB() << endl;
    cout << "Gx=" << G.x << endl;
    cout << "Gy=" << G.y << endl;
}
