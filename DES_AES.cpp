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

#include <codecvt>
#include <locale>

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

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
// using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#define N_ITER 10000

// Referece:
//https://stackoverflow.com/questions/4804298/how-to-convert-wstring-into-string
// Convert string to wstring
wstring s2ws(const std::string &str)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.from_bytes(str);
}

// Convert wstring to string
string ws2s(const std::wstring &wstr)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.to_bytes(wstr);
}

// Pretty print SecByteBlock as a hex wstring
void PrettyPrint(SecByteBlock byte_block)
{
	// Convert the byte_block to a hex wstring,
	// and print to console
	string encoded_string;
	StringSource(byte_block, byte_block.size(), true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	wstring wstr = s2ws(encoded_string);
	wcout << wstr << endl;
}

// Pretty print Cryptopp::byte array as a hex wstring
void PrettyPrint(CryptoPP::byte *bytes_array)
{
	// Convert the bytes_array to a hex wstring,
	// and print to console
	string encoded_string;
	StringSource(bytes_array, sizeof(bytes_array), true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	wstring wstr = s2ws(encoded_string);
	wcout << wstr << endl;
}

// Pretty print byte string as a hex wstring
void PrettyPrint(string str)
{
	// Convert byte string to a hex wstring,
	// and print to console.
	string encoded_string;
	StringSource(str, true,
				 new HexEncoder(
					 new StringSink(encoded_string)));
	wstring wstr = s2ws(encoded_string);
	wcout << wstr << endl;
}

// a template for encryption of various modes of operation
// Mode is 'm<DES>::Encryption' in which 'm' is the actual mode of DES
template <class Mode>
void Encrypt(const string &plain, Mode &e, string &cipher)
{
	cipher.clear();

	// StringSource acts as a pipeliner which intakes 'plain' as input,
	// uses StreamTransformationFilter to perform transformation on the input `plain`.

	// StreamTransformationFilter adds padding and invokes the Encryption object `e`
	// to perform encryption on the plaintext 'plain'.
	// The result (recovered plaintext) is stored in 'recovered' variable.
	StringSource(plain, true,
				 new StreamTransformationFilter(e, new StringSink(cipher)));
}

// a template for encryption of various modes of operation
// Mode is 'm<DES>::Decryption' in which 'm' is the actual mode of DES
template <class Mode>
void Decrypt(const string &cipher, Mode &d, string &recovered)
{
	recovered.clear();

	// StringSource acts as a pipeliner which intakes 'cipher" as input,
	// uses StreamTransformationFilter to perform transformation on the `cipher`.

	// StreamTransformationFilter removes padding and invokes the Decryption object `d`
	// to perform decryption on the ciphertext 'cipher'.
	// The result (recovered plaintext) is stored in 'recovered' variable.
	StringSource(cipher, true,
				 new StreamTransformationFilter(d,
												new StringSink(recovered)));
}

// An example of DES with CBC mode
void DES_CBC()
{
	// AutoSeededRandomPool is a random number generater and is seeded automatically.
	AutoSeededRandomPool prng;

	// SecByteBlock is a secure storage for senstitive data,
	// which will be zeroized or wiped after being destroyed
	// SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	SecByteBlock *key = new SecByteBlock(DES::DEFAULT_KEYLENGTH);

	// Generate random block of key.size() length, and store it in the Secure Byte Block of the "key"
	prng.GenerateBlock(*key, (*key).size());

	// Generate Initialization Vector with the length of BLOCKSIZE
	// CryptoPP::byte iv[DES::BLOCKSIZE];
	CryptoPP::byte *iv = new CryptoPP::byte[DES::BLOCKSIZE];
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
	PrettyPrint(*key);

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
		e.SetKeyWithIV(*key, (*key).size(), iv);
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
		d.SetKeyWithIV(*key, (*key).size(), iv);
		// d.SetKey(key, key.size());

		Decrypt(cipher, d, recovered);

		cout << "recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	delete key;
	delete[] iv;
}

// A template to perform encryption and decryption with various modes of operation that don't use IV
// The 'key', 'ciphertext' and 'recovered' will be changed in place.
// This function returns the time (in ms) to perform DES algorithm in 1 time.
template <class Encryption, class Decryption>
double *DES_nonIV(AutoSeededRandomPool &prng, SecByteBlock &key, string plaintext, string &ciphertext, string &recovered)
{
	// clock() return the current clock tick of the processor
	// Get starting clock tick of encryption
	int start_e = clock();

	// Generate new key
	prng.GenerateBlock(key, key.size());

	// Declare new Encryption object
	Encryption e;
	// Attach the key to the Encryption object
	e.SetKey(key, key.size());
	// Perform encryption
	Encrypt<Encryption>(plaintext, e, ciphertext);

	// Get ending clock tick of encryption
	int end_e = clock();

	// Get starting clock tick of decryption
	int start_d = clock();

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the Decryption object
	d.SetKey(key, key.size());
	// Perform decryption
	Decrypt<Decryption>(ciphertext, d, recovered);

	// Get ending clock tick of decryption
	int end_d = clock();

	// Calculate execution time (in ms) of encryption and decryption individually
	double *etime = new double[2];
	etime[0] = double(end_e - start_e) / CLOCKS_PER_SEC * 1000;
	etime[1] = double(end_d - start_d) / CLOCKS_PER_SEC * 1000;

	// Return execution time
	return etime;
}

// A template to perform encryption and decryption with various modes of operation that use IV
// The 'key', iv, 'ciphertext' and 'recovered' will be changed in place.
// This function return the time (in ms) to perform DES algorithm in 1 time.
template <class Encryption, class Decryption>
double *DES_IV(AutoSeededRandomPool &prng, SecByteBlock &key, CryptoPP::byte iv[], string plaintext, string &ciphertext, string &recovered)
{
	// clock() return the current clock tick of the processor
	// Get the starting clock tick of encryption
	int start_e = clock();

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

	// Get ending clock tick of encryption
	int end_e = clock();

	// Get starting clock tick of decryption
	int start_d = clock();

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the decryption object
	d.SetKeyWithIV(key, key.size(), iv);
	// Perform decryption
	Decrypt<Decryption>(ciphertext, d, recovered);

	// Get ending clock tick of decryption
	int end_d = clock();

	// Calculate execution time (in ms) of encryption and decryption individually
	double *etime = new double[2];
	etime[0] = double(end_e - start_e) / CLOCKS_PER_SEC * 1000;
	etime[1] = double(end_d - start_d) / CLOCKS_PER_SEC * 1000;

	return etime;
}

// A template to perform DES with various modes of operation that use IV.
// The 'key', iv, 'ciphertext' and 'recovered' are changed in place;
// therefore, the last value of them can be used to displayed on console as an example.
// The number of iteration is pre-defined as 'N_ITER'.
// This function returns the total execution time (in ms) of N_ITER iterations.
template <class Encryption, class Decryption>
double *LoopingIV(AutoSeededRandomPool &prng, SecByteBlock &key, CryptoPP::byte iv[], string plaintext, string &ciphertext, string &recovered)
{
	// first element relates to the encryption time
	// second element relates to the decryption time
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = DES_IV<Encryption, Decryption>(prng, key, iv, plaintext, ciphertext, recovered);
		sum[0] += etime[0];
		sum[1] += etime[1];
	}

	delete[] etime;
	return sum;
}

// A template to perform DES with various modes of operation that don't use IV.
// The 'key', iv, 'ciphertext' and 'recovered' are changed in place;
// therefore, the last value of them can be used to displayed on console as an example.
// The number of iteration is pre-defined as 'N_ITER'.
// This function returns the total execution time (in ms) of N_ITER iterations.
template <class Encryption, class Decryption>
double *Looping_nonIV(AutoSeededRandomPool &prng, SecByteBlock &key, string plaintext, string &ciphertext, string &recovered)
{
	// first element relates to the encryption time
	// second element relates to the decryption time
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = DES_nonIV<Encryption, Decryption>(prng, key, plaintext, ciphertext, recovered);
		sum[0] += etime[0];
		sum[1] += etime[1];
	}

	delete[] etime;
	return sum;
}

// Setup for Vietnamese language support
void SetupVietnameseSupport()
{
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
}

// Select mode of operation
int SelectMode()
{
	int mode;
	wcout << L"Chọn một mode of operation (nhập vào số tương ứng):\n";
	wcout << L"(1) ECB\n";
	wcout << L"(2) CBC\n";
	wcout << L"(3) CFB\n";
	wcout << L"(4) OFB\n";
	wcout << L"(5) CTR\n";
	wcout << L"> ";

	try
	{
		wcin >> mode;

		// if mode is of type 'int' but not within the valid range
		if (mode < 1 || mode > 5)
			return -1;

		// otherwise
		return mode;
	}
	catch (...)
	{
		// If an error occurs
		return -1;
	}
}

int SelectScheme()
{
	wcout << L"Vui lòng chọn scheme:" << endl;
	wcout << "(1) DES" << endl;
	wcout << "(2) AES" << endl;
	wcout << "> ";

	int scheme;
	try
	{
		wcin >> scheme;

		// if scheme if of type 'int' but not of valid values
		if (scheme != 1 && scheme != 2)
			return -1;

		// otherwise
		return scheme;
	}
	catch (...)
	{
		// if an error occurs
		return -1;
	}
}

int main(int argc, char *argv[])
{
	// Setup for Vietnamese language support
	SetupVietnameseSupport();

	// Declaration
	AutoSeededRandomPool prng;
	SecByteBlock *key = NULL;
	CryptoPP::byte *iv = NULL;

	wstring wplaintext, wciphertext, wrecoveredtext;
	string plaintext, ciphertext, recoveredtext;

	// Acquire plaintext
	wcout << L"Plaintext: ";
	getline(wcin, wplaintext);

	// Convert wstring 'wplaintext' to string 'plaintext' for the algorithm to work properly
	plaintext = ws2s(wplaintext);

	// Select scheme
	int scheme = SelectScheme();

	// Select mode
	int mode = SelectMode();
	bool valid = true;
	double *etime = NULL;

	if (scheme == 1)
	{
		key = new SecByteBlock(DES::DEFAULT_KEYLENGTH);
		iv = new CryptoPP::byte[DES::BLOCKSIZE];

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<DES>::Encryption, ECB_Mode<DES>::Decryption>(prng, *key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = LoopingIV<CBC_Mode<DES>::Encryption, CBC_Mode<DES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = LoopingIV<CFB_Mode<DES>::Encryption, CFB_Mode<DES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = LoopingIV<OFB_Mode<DES>::Encryption, OFB_Mode<DES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = LoopingIV<CTR_Mode<DES>::Encryption, CTR_Mode<DES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		default:
			wcout << L"'Mode of operation' không hợp lệ!\n";
			valid = false;
			break;
		}
	}
	else if (scheme == 2)
	{
		key = new SecByteBlock(AES::DEFAULT_KEYLENGTH);
		iv = new CryptoPP::byte[AES::BLOCKSIZE];

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption>(prng, *key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = LoopingIV<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = LoopingIV<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = LoopingIV<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = LoopingIV<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption>(prng, *key, iv, plaintext, ciphertext, recoveredtext);
			break;
		default:
			wcout << L"'Mode of operation' không hợp lệ!\n";
			valid = false;
			break;
		}
	}
	else
	{
		wcout << L"Scheme không hợp lệ" << endl;
		valid = false;
	}

	// Display an example of the algorithm in addition to the estimated time if inputs are valid.
	if (valid)
	{
		wcout << endl;
		wcout << L"Plaintext: " << wplaintext << endl;

		wcout << L"Key: ";
		PrettyPrint(*key);

		wcout << L"IV: ";
		PrettyPrint(iv);

		wcout << L"Ciphertext: ";
		PrettyPrint(ciphertext);

		wcout << L"Recovered text: " << s2ws(recoveredtext) << endl;
		wcout << "--------------------------------------------------" << endl;

		wcout << L"Tổng thời gian mã hóa trong 10000 vòng: " << etime[0] << " ms" << endl;
		wcout << L"Thời gian mã hóa trung bình của mỗi vòng: " << etime[0] / 10000 << " ms" << endl;

		wcout << endl;

		wcout << L"Tổng thời gian giải mã trong 10000 vòng: " << etime[1] << " ms" << endl;
		wcout << L"Thời gian giải mã trung bình của mỗi vòng: " << etime[1] / 10000 << " ms" << endl;

		delete[] etime;
	}

	return 0;
}
