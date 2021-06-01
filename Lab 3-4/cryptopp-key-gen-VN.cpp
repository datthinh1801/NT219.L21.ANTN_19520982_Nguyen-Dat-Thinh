// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe

/*Compute in Interger */
#include <cryptopp/integer.h>
#include "cryptopp/modarith.h"
#include <cryptopp/nbtheory.h> // a_times_b_mod_c
#include <iomanip>

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "helper.cpp"

int main(int argc, char **argv)
{
	SetupVietnameseSupport();
	AutoSeededRandomPool rnd;

	try
	{
		// Generate private key
		RSA::PrivateKey rsaPrivate;
		rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

		// Generate public key deriving from the private key
		RSA::PublicKey rsaPublic(rsaPrivate);

// Save keys to files
#ifdef _WIN32
		SavePrivateKey(".\\Lab 3-4\\rsa-private.key", rsaPrivate);
		SavePublicKey(".\\Lab 3-4\\rsa-public.key", rsaPublic);
#elif __linux__
		SavePrivateKey("./Lab 3-4/rsa-private.key", rsaPrivate);
		SavePublicKey("./Lab 3-4/rsa-public.key", rsaPublic);
#endif

		PrintKeys(rsaPrivate, rsaPublic);
		////////////////////////////////////////////////////////////////////////////////////
		/* Check the keys */
		CryptoPP::Integer n, p, q, e, d;
		n = rsaPublic.GetModulus();
		p = rsaPrivate.GetPrime1();
		q = rsaPrivate.GetPrime2();
		CryptoPP::ModularArithmetic ma(n);
		//wcout << "Modunlo  n= " << integer_to_wstring(rsaPublic.GetModulus()) << endl;
		//wcout << " p.q=" << integer_to_wstring(ma.Multiply(p, q)) << endl;
		//wcout << integer_to_wstring(a_times_b_mod_c(p,q,n)) << endl;

		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 2048);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

#ifdef _WIN32
		SavePrivateKey(".\\Lab 3-4\\dsa-private.key", dsaPrivate);
		SavePublicKey(".\\Lab 3-4\\dsa-public.key", dsaPublic);
#elif __linux__
		SavePrivateKey("./Lab 3-4/dsa-private.key", dsaPrivate);
		SavePublicKey("./Lab 3-4/dsa-public.key", dsaPublic);
#endif

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

#ifdef _WIN32
		SavePrivateKey(".\\Lab 3-4\\rsa-roundtrip.key", r1);
		LoadPrivateKey(".\\Lab 3-4\\rsa-roundtrip.key", r2);
#elif __linux__
		SavePrivateKey("./Lab 3-4/rsa-roundtrip.key", r1);
		LoadPrivateKey("./Lab 3-4/rsa-roundtrip.key", r2);
#endif

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if (r1.GetModulus() != r2.GetModulus() ||
			r1.GetPublicExponent() != r2.GetPublicExponent() ||
			r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}

		////////////////////////////////////////////////////////////////////////////////////

		wcout << "Successfully generated and saved RSA and DSA keys" << endl;
	}

	catch (CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch (std::exception &e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}
