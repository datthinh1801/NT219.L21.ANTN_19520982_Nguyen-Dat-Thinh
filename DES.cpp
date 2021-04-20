// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

void PrettyPrint(SecByteBlock byte_block)
{
	// Convert bytes from byte_block to a hex string,
	// and print to console
	string encoded_string;
	StringSource(byte_block, byte_block.size(), true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	cout << encoded_string << endl;
}

void PrettyPrint(CryptoPP::byte *bytes_array)
{
	// Convert bytes from bytes_array to a hex string,
	// and print to console
	string encoded_string;
	StringSource(bytes_array, sizeof(bytes_array), true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	cout << encoded_string << endl;
}

void PrettyPrint(string str)
{
	// Convert byte string to hex string,
	// and print to console.
	string encoded_string;
	StringSource(str, true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	cout << encoded_string << endl;
}

// a template for encryption of various modes of operation
template <class Mode>
void Encrypt(const string &plain, Mode &e, string &cipher)
{
	cipher.clear();

	// StringSource acts as a pipeliner which intakes "plain" as input,
	// uses StreamTransformationFilter to add padding and perform encryption on the cipher,
	// the result (recovered plaintext) is stored in "recovered" variable.
	StringSource(plain, true,
				 new StreamTransformationFilter(e, new StringSink(cipher)));
}

// a template for encryption of various modes of operation
template <class Mode>
void Decrypt(const string &cipher, Mode &d, string &recovered)
{
	recovered.clear();

	// StringSource acts as a pipeliner which intakes 'cipher" as input,
	// uses StreamTransformationFilter to remove padding and perform decryption on the cipher,
	// the result (recovered plaintext) is stored in "recovered" variable.
	StringSource(cipher, true,
				 new StreamTransformationFilter(d,
												new StringSink(recovered)));
}

int DES_CBC()
{
	// Get starting time.
	int start_time = clock();

	// AutoSeededRandomPool is a random number generater and is seeded automatically.
	AutoSeededRandomPool prng;

	// SecByteBlock is a secure storage for senstitive data,
	// which will be zeroized or wiped after being destroyed
	SecByteBlock key(DES::DEFAULT_KEYLENGTH);

	// Generate random block of key.size() length, and store it in the Secure Byte Block of the "key"
	prng.GenerateBlock(key, key.size());

	// Generate Initialization Vector with the length of BLOCKSIZE
	CryptoPP::byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	// Declare plaintext, ciphertext
	string plain;
	string cipher, encoded, recovered;

	// cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
	// cout << "block size: " << DES::BLOCKSIZE << endl;

	// Pretty print key:
	// Convert bytes from the Secure Block of the "key" to a hex string stored in "encoded" variable
	cout << "Key : ";
	PrettyPrint(key);

	// Pretty print iv:
	// Convert bytes from the Secure Block of the "iv" to a hex string stored in "encoded" variable
	cout << "IV : ";
	PrettyPrint(iv);

	try
	{
		cout << "plain-text: ";
		std::getline(cin, plain);

		// Create an encryption object of DES, using CBC mode of operation
		CBC_Mode<DES>::Encryption e;

		// Set the key for the encryption, and attach Initialization vector
		e.SetKeyWithIV(key, key.size(), iv);
		Encrypt(plain, e, cipher);

		// At this point, cipher stores bytes of the encrypted text,
		// so it needs to be encoded by HexEncoder to be betther printed
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Pretty print
	cout << "Cipher-text : ";
	PrettyPrint(cipher);

	try
	{
		CBC_Mode<DES>::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);
		// d.SetKey(key, key.size());

		Decrypt(cipher, d, recovered);

		cout << "recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	int end_time = clock();
	return end_time - start_time;
}

int main(int argc, char *argv[])
{
	DES_CBC();
	return 0;
}
