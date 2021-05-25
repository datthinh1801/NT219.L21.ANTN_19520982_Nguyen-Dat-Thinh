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

#include <limits>

#include <string>
using std::string;

#include <codecvt>
#include <locale>

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::AAD_CHANNEL;
using CryptoPP::BufferedTransformation;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <assert.h>

#define N_ITER 10000

// Referece:
// https://stackoverflow.com/questions/4804298/how-to-convert-wstring-into-string
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
	try
	{
		StringSource(plain, true,
					 new StreamTransformationFilter(e, new StringSink(cipher)));
	}
	catch (const CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
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
	try
	{
		StringSource(cipher, true,
					 new StreamTransformationFilter(d,
													new StringSink(recovered)));
	}
	catch (const CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
}

// The 'key', 'ciphertext' and 'recovered' will be changed in place.
// This function returns the time (in ms) to perform DES algorithm in 1 time.
template <class Encryption, class Decryption>
double *Encrypt_Decrypt(AutoSeededRandomPool &prng, SecByteBlock &key, string plaintext, string &ciphertext, string &recovered)
{
	// clock() return the current clock tick of the processor
	// Get starting clock tick of encryption
	int start_e = clock();

	// Declare new Encryption object
	Encryption e;
	// Attach the key to the Encryption object
	try
	{
		e.SetKey(key, key.size());
	}
	catch (CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
	// Perform encryption
	Encrypt<Encryption>(plaintext, e, ciphertext);

	// Get ending clock tick of encryption
	int end_e = clock();

	// Get starting clock tick of decryption
	int start_d = clock();

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the Decryption object
	try
	{
		d.SetKey(key, key.size());
	}
	catch (const CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
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
double *Encrypt_Decrypt_withIV(AutoSeededRandomPool &prng, SecByteBlock &key, SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered)
{
	// clock() return the current clock tick of the processor
	// Get the starting clock tick of encryption
	int start_e = clock();

	// Declare new Encryption object
	Encryption e;
	// Attach the key to the Encryption object
	try
	{
		e.SetKeyWithIV(key, key.size(), iv);
	}
	catch (const CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}

	// Perform encryption
	Encrypt<Encryption>(plaintext, e, ciphertext);

	// Get ending clock tick of encryption
	int end_e = clock();

	// Get starting clock tick of decryption
	int start_d = clock();

	// Declare the new Decryption object
	Decryption d;
	// Attach the key to the decryption object
	try
	{
		d.SetKeyWithIV(key, key.size(), iv);
	}
	catch (const CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
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
double *LoopingIV(AutoSeededRandomPool &prng, SecByteBlock &key, SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered)
{
	// first element relates to the encryption time
	// second element relates to the decryption time
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = Encrypt_Decrypt_withIV<Encryption, Decryption>(prng, key, iv, plaintext, ciphertext, recovered);
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
		etime = Encrypt_Decrypt<Encryption, Decryption>(prng, key, plaintext, ciphertext, recovered);
		sum[0] += etime[0];
		sum[1] += etime[1];
	}

	delete[] etime;
	return sum;
}

template <class Encryption, class Decryption>
double *Encrypt_Decrypt_withAuthentication(AutoSeededRandomPool &prng, SecByteBlock &key, SecByteBlock &iv, string plaintext, string auth, string &ciphertext, string &recovered_plaintext, string &recovered_auth)
{
	// [START ENCRYPTION]
	int start_e = clock();

	const int TAG_SIZE = 16;
	try
	{
		Encryption enc;
		enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
		enc.SpecifyDataLengths(auth.size(), plaintext.size(), 0);

		AuthenticatedEncryptionFilter ef(enc,
										 new StringSink(ciphertext));

		ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte *)auth.data(), auth.size());
		ef.ChannelMessageEnd(AAD_CHANNEL);

		ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)plaintext.data(), plaintext.size());
		ef.ChannelMessageEnd(DEFAULT_CHANNEL);
	}
	catch (CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
	}
	int end_e = clock();
	// [END ENRYPTION]

	// [START DECRYPTION]
	int start_d = clock();
	try
	{
		string encrypted_data = ciphertext.substr(0, ciphertext.size() - TAG_SIZE);
		string mac = ciphertext.substr(ciphertext.size() - TAG_SIZE);

		GCM<AES>::Decryption dec;
		dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
		dec.SpecifyDataLengths(recovered_auth.size(), encrypted_data.size(), 0);

		recovered_auth = auth;

		AuthenticatedDecryptionFilter df(dec, NULL,
										 AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
											 AuthenticatedDecryptionFilter::THROW_EXCEPTION,
										 TAG_SIZE);
		df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)mac.data(), mac.size());
		df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte *)auth.data(), auth.size());
		df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)encrypted_data.data(), encrypted_data.size());

		df.ChannelMessageEnd(AAD_CHANNEL);
		df.ChannelMessageEnd(DEFAULT_CHANNEL);

		// Check data's integrity
		bool b = false;
		b = df.GetLastResult();
		assert(true == b);

		df.SetRetrievalChannel(DEFAULT_CHANNEL);
		size_t n = (size_t)df.MaxRetrievable();
		recovered_plaintext.resize(n);

		if (n > 0)
		{
			df.Get((CryptoPP::byte *)recovered_plaintext.data(), n);
		}
		assert(plaintext == recovered_plaintext);
	}
	catch (CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
	}
	int end_d = clock();
	// [END DECRYPTION]

	double *etime = new double[2];
	etime[0] = double(end_e - start_e) / CLOCKS_PER_SEC * 1000;
	etime[1] = double(end_d - start_d) / CLOCKS_PER_SEC * 1000;
	return etime
}

template <class Encryption, class Decryption>
double *Looping_Authentication(AutoSeededRandomPool &prng, SecByteBlock &key, string plaintext, string auth, string &ciphertext, string &recovered)
{
}

// Setup for Vietnamese support
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
	wcout << L"(6) CBC_CTS\n";
	wcout << L"(7) XTS\n";
	wcout << L"(8) GCM\n";
	wcout << L"(9) CCM\n";
	wcout << L"> ";

	try
	{
		wcin >> mode;

		// if mode is of type 'int' but not within the valid range
		if (mode < 1 || mode > 9)
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

// Select DES/AES
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

// Select AES key size
int SelectKeySize()
{
	/*
    |----------|----------|
    | Key size | # rounds |
    |----------|----------|
    | 128 bits | 10       |
    | 192 bits | 12       |
    | 256 bits | 14       |
    |----------|----------|
    */
	const int key_sizes[] = {16, 24, 32, 64};
	wcout << L"Chọn key size cho AES:" << endl;
	wcout << L"(1) 128 bits ~ 16 bytes (default)\n";
	wcout << L"(2) 192 bits ~ 24 bytes\n";
	wcout << L"(3) 256 bits ~ 32 bytes\n";
	wcout << L"(4) 512 bits ~ 64 bytes (XTS only)\n";
	wcout << L"\n> ";

	int option;
	try
	{
		wcin >> option;

		if (option >= 1 && option <= 4)
		{
			return key_sizes[option - 1];
		}
		else
		{
			return -1;
		}
	}
	catch (...)
	{
		return -1;
	}
}

// Acquire a string from console and convert to SecByteBlock in place.
// Return true if succeed.
bool GraspInputFromConsole(SecByteBlock &block, int block_size, wstring which)
{
	try
	{
		// Acquire a string from console
		wstring winput;
		wcout << L"Nhập " + which + L": ";
		fflush(stdin);
		getline(wcin, winput);
		string input = ws2s(winput);

		// Convert to bytes
		StringSource ss(input, false);
		CryptoPP::ArraySink bytes_block(block, block_size);
		ss.Detach(new Redirector(bytes_block));
		ss.Pump(block_size);

		return true;
	}
	catch (...)
	{
		return false;
	}
}

// Generate the key/IV based on option (manual or random).
// Return true if succeed.
bool GenerateSecByteBlock(SecByteBlock &block, int block_size, wstring which)
{
	wcout << L"Nhập " + which + L" hay random " + which + L":\n";
	wcout << L"(1) Nhập " + which << endl;
	wcout << L"(2) Random " + which << endl;
	wcout << L"\n> ";

	int option;
	try
	{
		wcin >> option;

		if (option == 1)
		{
			block = SecByteBlock(block_size);
			if (GraspInputFromConsole(block, block_size, which))
				return true;
			else
				return false;
		}
		else if (option == 2)
		{
			AutoSeededRandomPool prng;
			block = SecByteBlock(block_size);
			prng.GenerateBlock(block, block_size);
			return true;
		}
		else
		{
			return false;
		}
	}
	catch (...)
	{
		return false;
	}
}

int main(int argc, char *argv[])
{
	// Setup for Vietnamese support
	SetupVietnameseSupport();

	// Declaration
	AutoSeededRandomPool prng;
	CryptoPP::SecByteBlock key;
	CryptoPP::SecByteBlock iv;

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
	double *etime = NULL;

	int key_size;
	int iv_size;

	// DES
	if (scheme == 1)
	{
		key_size = DES::DEFAULT_KEYLENGTH;
		if (!GenerateSecByteBlock(key, key_size, L"key"))
		{
			wcout << L"Đã xảy ra lỗi khi nhập key!\n";
			return 0;
		}

		iv_size = DES::BLOCKSIZE;
		if (!GenerateSecByteBlock(iv, iv_size, L"IV"))
		{
			wcout << L"Đã xãy ra lỗi khi nhập IV!\n";
			return 0;
		}

		// Write key to file
		StringSource ss(key, key.size(), true, new FileSink("key.key"));

		// Read key from file
		// FileSource fs("des_key.key", false);
		// CryptoPP::ArraySink bytes_key(key, key_size);
		// fs.Detach(new Redirector(bytes_key));
		// fs.Pump(key_size);

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<DES>::Encryption, ECB_Mode<DES>::Decryption>(prng, key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = LoopingIV<CBC_Mode<DES>::Encryption, CBC_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = LoopingIV<CFB_Mode<DES>::Encryption, CFB_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = LoopingIV<OFB_Mode<DES>::Encryption, OFB_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = LoopingIV<CTR_Mode<DES>::Encryption, CTR_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 6:
			etime = LoopingIV<CBC_CTS_Mode<DES>::Encryption, CBC_CTS_Mode<DES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		default:
			wcout << L"'Mode of operation' không hợp lệ!\n";
			return 0;
		}
	}
	// AES
	else if (scheme == 2)
	{
		key_size = SelectKeySize();

		if (key_size == -1 || (key_size == 64 && mode != 7))
		{
			wcout << L"Key size không hợp lệ!" << endl;
			return 0;
		}

		if (!GenerateSecByteBlock(key, key_size, L"key"))
		{
			wcout << L"Đã xảy ra lỗi khi nhập key!\n";
			return 0;
		}

		iv_size = AES::BLOCKSIZE;
		if (!GenerateSecByteBlock(iv, iv_size, L"IV"))
		{
			wcout << L"Đã xảy ra lỗi khi nhập IV!\n";
			return 0;
		}

		// Write key to file
		StringSource ss(key, key.size(), true, new FileSink("aes_key.key"));

		// Read key from file
		// FileSource fs("aes_key.key", false);
		// CryptoPP::ArraySink bytes_key(key, key_size);
		// fs.Detach(new Redirector(bytes_key));
		// fs.Pump(key_size);

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption>(prng, key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = LoopingIV<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = LoopingIV<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = LoopingIV<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = LoopingIV<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 6:
			etime = LoopingIV<CBC_CTS_Mode<AES>::Encryption, CBC_CTS_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 7:
			etime = LoopingIV<XTS_Mode<AES>::Encryption, XTS_Mode<AES>::Decryption>(prng, key, iv, plaintext, ciphertext, recoveredtext);
			break;
		default:
			wcout << L"'Mode of operation' không hợp lệ!\n";
			return 0;
		}
	}
	// Otherwise
	else
	{
		wcout << L"Scheme không hợp lệ" << endl;
		return 0;
	}

	// Display an example of the algorithm in addition to the estimated time if inputs are valid.
	wcout << endl;
	wcout << L"Plaintext: " << wplaintext << endl;

	wcout << L"Key: ";
	PrettyPrint(key);

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

	return 0;
}
