// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe

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

#include "base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

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

		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);

		////////////////////////////////////////////////////////////////////////////////////

		// http://www.cryptopp.com/docs/ref/struct_d_s_a.html
		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 1024);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if(r1.GetModulus() != r2.GetModulus() ||
		   r1.GetPublicExponent() != r2.GetPublicExponent() ||
		   r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}
		
		////////////////////////////////////////////////////////////////////////////////////

		cout << "Successfully generated and saved RSA and DSA keys" << endl;
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

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

