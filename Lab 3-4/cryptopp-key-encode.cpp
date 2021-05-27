// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-encode.cpp -o cryptopp-key-encode.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-encode.cpp -o cryptopp-key-encode.exe -lcryptopp && strip --strip-all cryptopp-key-encode.exe

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <queue.h>
using CryptoPP::ByteQueue;

#include <files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "dsa.h"
using CryptoPP::DSA;

#include "rsa.h"
using CryptoPP::RSA;

#include <cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key);
void EncodePublicKey(const string& filename, const RSA::PublicKey& key);
void Encode(const string& filename, const BufferedTransformation& bt);

void DecodePrivateKey(const string& filename, RSA::PrivateKey& key);
void DecodePublicKey(const string& filename, RSA::PublicKey& key);
void Decode(const string& filename, BufferedTransformation& bt);

int main(int argc, char** argv)
{
	std::ios_base::sync_with_stdio(false);

	// http://www.cryptopp.com/docs/ref/class_auto_seeded_random_pool.html
	AutoSeededRandomPool rnd;

	try
	{
		// http://www.cryptopp.com/docs/ref/rsa_8h.html
		RSA::PrivateKey rsaPrivate;
		rsaPrivate.GenerateRandomWithKeySize(rnd, 2048);

		RSA::PublicKey rsaPublic(rsaPrivate);

		EncodePrivateKey("rsa-private.key", rsaPrivate);
		EncodePublicKey("rsa-public.key", rsaPublic);				

		cout << "Successfully generated and saved RSA keys" << endl;

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey k1;
		DecodePrivateKey("rsa-private.key", k1);

		RSA::PublicKey k2;
		DecodePublicKey("rsa-public.key", k2);

		cout << "Successfully loaded RSA keys" << endl;

		////////////////////////////////////////////////////////////////////////////////////

		if(!k1.Validate(rnd, 3))
			throw runtime_error("Rsa private key validation failed");

		if(!k2.Validate(rnd, 3))
			throw runtime_error("Rsa public key validation failed");

		cout << "Successfully validated RSA keys" << endl;

		////////////////////////////////////////////////////////////////////////////////////

		if(rsaPrivate.GetModulus() != k1.GetModulus() ||
		   rsaPrivate.GetPublicExponent() != k1.GetPublicExponent() ||
		   rsaPrivate.GetPrivateExponent() != k1.GetPrivateExponent())
		{
		    throw runtime_error("private key data did not round trip");
		}

		if(rsaPublic.GetModulus() != k2.GetModulus() ||
		   rsaPublic.GetPublicExponent() != k2.GetPublicExponent())
		{
		    throw runtime_error("public key data did not round trip");
		}

		cout << "Successfully round-tripped RSA keys" << endl;

		////////////////////////////////////////////////////////////////////////////////////
	}

	catch(CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.DEREncodePrivateKey(queue);

	Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.DEREncodePublicKey(queue);

	Encode(filename, queue);
}

void Encode(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void Decode(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}


