// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
#include <io.h>
#include <fcntl.h>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::getline;
using std::wcin;
using std::wcout;
using std::wstring;

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
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
// using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CTR_Mode;
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
	// uses StreamTransformationFilter to perform transformation on the input `plain`.

	// StreamTransformationFilter adds padding and invokces the Mode `e` to perform encryption on the cipher,
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
	// uses StreamTransformationFilter to perform transformation on the `cipher`.

	// StreamTransformationFilter removes padding and invokdes Mode `d` to perform decryption on the cipher,
	// the result (recovered plaintext) is stored in "recovered" variable.
	StringSource(cipher, true,
				 new StreamTransformationFilter(d,
												new StringSink(recovered)));
}

void DES_CBC()
{
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

	// size of bytes
	// cout << "key length: " << key.size() << endl;
	// cout << "block size: " << sizeof(iv) << endl;

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
		getline(cin, plain);

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
}

template <class Encryption, class Decryption>
double DES_nonIV(AutoSeededRandomPool &prng, SecByteBlock &key, string plaintext, string &ciphertext)
{
	// clock() return the current clock tick of the processor
	int start = clock();

	// Generate new key
	prng.GenerateBlock(key, key.size());

	// Declare new Encryption object
	Encryption e;
	// Attach the key to the Encryption object
	e.SetKey(key, key.size());
	// Perform encryption
	Encrypt<Encryption>(plaintext, e, ciphertext);

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the Encryption object
	d.SetKey(key, key.size());
	// Perform decryption
	Decrypt<Decryption>(ciphertext, d, plaintext);

	// Get ending clock tick
	int end = clock();

	// Return execution time in miliseconds
	return double(end - start) / CLOCKS_PER_SEC * 1000;
}

template <class Encryption, class Decryption>
double DES_IV(AutoSeededRandomPool &prng, SecByteBlock &key, CryptoPP::byte iv[], string plaintext, string &ciphertext)
{
	// clock() return the current clock tick of the processor
	int start = clock();

	// Generate new key
	prng.GenerateBlock(key, key.size());

	// Generate IV
	prng.GenerateBlock(iv, sizeof(iv));

	// Declare new Encryption object
	Encryption e;
	// Attach the key to the Encryption object
	e.SetKeyWithIV(key, key.size(), iv);
	// Perform encryption
	Encrypt<Encryption>(plaintext, e, ciphertext);

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the Encryption object
	d.SetKeyWithIV(key, key.size(), iv);
	// Perform decryption
	Decrypt<Decryption>(ciphertext, d, plaintext);

	// Get ending clock tick
	int end = clock();

	// Return execution time in miliseconds
	return double(end - start) / CLOCKS_PER_SEC * 1000;
}

double LoopingIV(AutoSeededRandomPool &prng, SecByteBlock &key, CryptoPP::byte iv[], string plaintext, string &ciphertext)
{
	double sum = 0;
	int time;

	for (int i = 0; i < 10000; ++i)
	{
		// time = DES_nonIV<ECB_Mode<DES>::Encryption, ECB_Mode<DES>::Decryption>(prng, key, plaintext);
		time = DES_IV<CBC_Mode<DES>::Encryption, CBC_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext);
		sum += time;
	}
	return sum;
}

void SetupVietnameseSupport()
{
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
	// std::wcout << L"Tiếng Việt có dấu" << std::endl;
	// std::wstring test;
	// std::wcout << L"Hãy nhập vào một chuỗi ký tự:" << std::endl;
	// std::getline(std::wcin, test);
	// std::wcout << L"Chuỗi ký tự mà bạn vừa mới nhập:" << std::endl;
	// std::wcout << test << std::endl;
}

int SelectMode()
{
	int mode;
	wcout << "Chọn mode of operation (nhập vào số tương ứng):\n";
	cout << "(1) ECB\n";
	cout << "(2) CBC\n";
	cout << "(3) CFB\n";
	cout << "(4) OFB\n";
	cout << "(5) CTR\n";

	cin >> mode;

	if (mode < 1 || mode > 5)
		return -1;
	return mode;
}

int main(int argc, char *argv[])
{
	// SetupVietnameseSupport();
	AutoSeededRandomPool prng;
	SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	CryptoPP::byte iv[DES::BLOCKSIZE];

	string plaintext, ciphertext;

	cout << "Plaintext: ";
	getline(cin, plaintext);

	double etime = LoopingIV(prng, key, iv, plaintext, ciphertext);

	cout << "Key: ";
	PrettyPrint(key);

	cout << "IV: ";
	PrettyPrint(iv);

	cout << "Ciphertext: ";
	PrettyPrint(ciphertext);

	cout << "Execution time of 10000 rounds: " << etime << " ms" << endl;
	cout << "Average execution time of each round: " << etime / 10000 << " ms" << endl;

	return 0;
}
