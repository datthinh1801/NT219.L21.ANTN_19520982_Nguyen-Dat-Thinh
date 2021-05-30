// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
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
double *Encrypt_Decrypt(const SecByteBlock &key, string plaintext, string &ciphertext, string &recovered)
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
double *Encrypt_Decrypt_withIV(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered)
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
double *Looping_IV(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered)
{
	// first element relates to the encryption time
	// second element relates to the decryption time
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = Encrypt_Decrypt_withIV<Encryption, Decryption>(key, iv, plaintext, ciphertext, recovered);
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
double *Looping_nonIV(const SecByteBlock &key, string plaintext, string &ciphertext, string &recovered)
{
	// first element relates to the encryption time
	// second element relates to the decryption time
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = Encrypt_Decrypt<Encryption, Decryption>(key, plaintext, ciphertext, recovered);
		sum[0] += etime[0];
		sum[1] += etime[1];
	}

	delete[] etime;
	return sum;
}

template <class Encryption, class Decryption>
double *Encrypt_Decrypt_withAuthentication(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string auth, string &ciphertext, string &recovered_plaintext, string &recovered_auth)
{
	ciphertext.clear();
	recovered_plaintext.clear();

	// [START ENCRYPTION]
	int start_e = clock();

	const int TAG_SIZE = 8;
	try
	{
		Encryption enc;
		// Attach key and IV
		enc.SetKeyWithIV(key, key.size(), iv, iv.size());
		// Not required for GCM, but required for CCM
		enc.SpecifyDataLengths(auth.size(), plaintext.size(), 0);

		AuthenticatedEncryptionFilter ef(enc,
										 new StringSink(ciphertext), false, TAG_SIZE);

		// Put authenticated data to the authenticated channel which only provides authentication
		ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte *)auth.data(), auth.size());
		ef.ChannelMessageEnd(AAD_CHANNEL);

		// Put plaintext to the default channel which provides confidentiality and authentiation
		ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)plaintext.data(), plaintext.size());
		ef.ChannelMessageEnd(DEFAULT_CHANNEL);
	}
	catch (CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
	int end_e = clock();
	// [END ENRYPTION]

	// [START DECRYPTION]
	int start_d = clock();
	try
	{
		// Split the ciphertext into encrypted data and MAC value
		string encrypted_data = ciphertext.substr(0, ciphertext.size() - TAG_SIZE);
		string mac = ciphertext.substr(ciphertext.size() - TAG_SIZE);

		// Authenticated data is sent via a clear channel
		recovered_auth = auth;

		Decryption dec;
		// Attach the key and IV
		dec.SetKeyWithIV(key, key.size(), iv, iv.size());
		dec.SpecifyDataLengths(recovered_auth.size(), encrypted_data.size(), 0);

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

		// Retrieve confidential data from channel
		df.SetRetrievalChannel(DEFAULT_CHANNEL);
		size_t n = (size_t)df.MaxRetrievable();
		recovered_plaintext.resize(n);

		if (n > 0)
		{
			df.Get((CryptoPP::byte *)recovered_plaintext.data(), n);
		}
	}
	catch (CryptoPP::Exception &ex)
	{
		wcout << ex.what() << endl;
		exit(1);
	}
	int end_d = clock();
	// [END DECRYPTION]

	double *etime = new double[2];
	etime[0] = double(end_e - start_e) / CLOCKS_PER_SEC * 1000;
	etime[1] = double(end_d - start_d) / CLOCKS_PER_SEC * 1000;
	return etime;
}

template <class Encryption, class Decryption>
double *Looping_Authentication(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string auth, string &ciphertext, string &recovered_plaintext, string &recovered_auth)
{
	double *sum = new double[2];
	double *etime = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < N_ITER; ++i)
	{
		etime = Encrypt_Decrypt_withAuthentication<Encryption, Decryption>(key, iv, plaintext, auth, ciphertext, recovered_plaintext, recovered_auth);
		sum[0] += etime[0];
		sum[1] += etime[1];
	}

	delete[] etime;
	return sum;
}

string GraspAuthenticatedData()
{
	wstring wadata;
	wcout << L"Authenticated data: ";
	fflush(stdin);
#ifdef __linux__
	getline(wcin, wadata);
	getline(wcin, wadata);
#endif
	getline(wcin, wadata);
	string adata = ws2s(wadata);
	return adata;
}

// Setup for Vietnamese support
void SetupVietnameseSupport()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}

// Select mode of operation
int SelectMode(bool is_AES)
{
	int mode;
	wcout << L"Chọn một mode of operation (nhập vào số tương ứng):\n";
	wcout << L"(1) ECB\n";
	wcout << L"(2) CBC\n";
	wcout << L"(3) CFB\n";
	wcout << L"(4) OFB\n";
	wcout << L"(5) CTR\n";

	if (is_AES)
	{
		wcout << L"(6) XTS\n";
		wcout << L"(7) GCM\n";
		wcout << L"(8) CCM\n";
	}
	wcout << L"> ";

	try
	{
		wcin >> mode;

		// if mode is of type 'int' but not within the valid range
		if (mode < 1 || (mode > 8 && is_AES) || (mode > 5 && !is_AES))
		{
			wcout << L"Mode không hợp lệ!" << endl;
			exit(1);
		}

		// otherwise
		return mode;
	}
	catch (...)
	{
		// If an error occurs
		wcout << L"Mode không hợp lệ!" << endl;
		exit(1);
	}
}

// Select DES/AES
int SelectScheme()
{
	wcout << L"Vui lòng chọn scheme:" << endl;
	wcout << L"(1) DES" << endl;
	wcout << L"(2) AES" << endl;
	wcout << L"> ";

	int scheme;
	try
	{
		wcin >> scheme;

		// if scheme if of type 'int' but not of valid values
		if (scheme != 1 && scheme != 2)
		{
			wcout << L"Scheme không hợp lệ!" << endl;
			exit(1);
		}

		// otherwise
		return scheme;
	}
	catch (...)
	{
		// if an error occurs
		wcout << L"Scheme không hợp lệ!" << endl;
		exit(1);
	}
}

// Select AES key size
int SelectKeySize(int mode)
{
	const int key_sizes[] = {16, 24, 32, 64};
	wcout << L"Chọn key size cho AES:" << endl;
	if (mode != 6)
	{
		wcout << L"(1) 128 bits ~ 16 bytes (default)\n";
		wcout << L"(2) 192 bits ~ 24 bytes\n";
		wcout << L"(3) 256 bits ~ 32 bytes\n";
	}
	if (mode == 6)
	{
		wcout << L"(1) 256 bits ~ 32 bytes\n";
		wcout << L"(2) 512 bits ~ 64 bytes\n";
	}
	wcout << L"> ";

	int option;
	try
	{
		wcin >> option;

		if (mode != 6 && option >= 1 && option <= 3)
		{
			return key_sizes[option - 1];
		}
		else if (mode == 6 && option >= 1 && option <= 2)
		{
			return key_sizes[option + 1];
		}
		else
		{
			wcout << L"Key size không hợp lệ!" << endl;
			exit(1);
		}
	}
	catch (...)
	{
		wcout << L"Key size không hợp lệ!" << endl;
		exit(1);
	}
}

// Select IV's size in AES
int SelectIVSize(int mode)
{
	wcout << L"Chọn IV size hay sử dụng giá trị mặc định:" << endl;
	wcout << L"(1) Tự chọn" << endl;
	wcout << L"(2) Sử dụng giá trị mặc định" << endl;
	wcout << L"> ";

	int option, sz;

	try
	{
		wcin >> option;

		if (option == 1)
		{
			if (mode == 7)
			{
				wcout << L"IV size: ";
				wcin >> sz;
			}
			else if (mode == 8)
			{
				wcout << L"IV size [7, 13]: ";
				wcin >> sz;

				if (sz < 7 || sz > 13)
				{
					wcout << L"IV size không hợp lệ!" << endl;
					exit(1);
				}
			}
		}
		else if (option == 2)
		{
			if (mode == 7)
			{
				sz = AES::BLOCKSIZE;
			}
			else if (mode == 8)
			{
				sz = 8;
			}
		}
	}
	catch (const std::exception &e)
	{
		wcout << L"IV size không hợp lệ!" << endl;
		exit(1);
	}

	return sz;
}

// Acquire a string from console and convert to SecByteBlock in place.
// Return true if succeed.
void GraspInputFromConsole(SecByteBlock &block, int block_size, wstring which)
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
	}
	catch (...)
	{
		wcout << L"Đã xảy ra lỗi trong quá trình nhập!" << endl;
		exit(1);
	}
}

// Generate the key/IV based on option (manual or random).
// Return true if succeed.
void GenerateSecByteBlock(SecByteBlock &block, int block_size, wstring which, int scheme)
{
	wcout << L"Nhập " + which + L", random hay đọc " + which + L" từ file:\n";
	wcout << L"(1) Nhập " + which << endl;
	wcout << L"(2) Random " + which << endl;
	wcout << L"(3) Đọc " + which << L" từ file" << endl;
	wcout << L"> ";

	int option;
	try
	{
		wcin >> option;

		if (option == 1)
		{
			block = SecByteBlock(block_size);
			GraspInputFromConsole(block, block_size, which);
		}
		else if (option == 2)
		{
			AutoSeededRandomPool prng;
			block = SecByteBlock(block_size);
			prng.GenerateBlock(block, block_size);
		}
		else if (option == 3)
		{
			block = SecByteBlock(block_size);
			if (scheme == 1 && which == L"key")
			{
#ifdef _WIN32
				FileSource fs(".\\Lab 1-2\\des_key.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#elif __linux__
				FileSource fs("./Lab 1-2/des_key.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);

#endif
			}
			else if (scheme == 1 && which == L"IV")
			{
#ifdef _WIN32
				FileSource fs(".\\Lab 1-2\\des_iv.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#elif __linux__
				FileSource fs("./Lab 1-2/des_iv.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#endif
			}
			else if (scheme == 2 && which == L"key")
			{
#ifdef _WIN32
				FileSource fs(".\\Lab 1-2\\aes_key.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#elif __linux__
				FileSource fs("./Lab 1-2/aes_key.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#endif
			}
			else
			{
#ifdef _WIN32
				FileSource fs(".\\Lab 1-2\\aes_iv.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#elif __linux__
				FileSource fs("./Lab 1-2/aes_iv.key", false);
				CryptoPP::ArraySink bytes_block(block, block_size);
				fs.Detach(new Redirector(bytes_block));
				fs.Pump(block_size);
#endif
			}
		}
		else
		{
			wcout << L"Lựa chọn không hợp lệ!" << endl;
			exit(1);
		}
	}
	catch (...)
	{
		wcout << L"Đã xảy ra lỗi trong quá trình tạo block!" << endl;
		exit(1);
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
	int mode;
	if (scheme == 1)
	{
		mode = SelectMode(false);
	}
	else if (scheme == 2)
	{
		mode = SelectMode(true);
	}

	double *etime = NULL;
	int key_size, iv_size;

	string auth, recovered_auth;

	// If an authentication mode is selected
	if (mode == 7 || mode == 8)
	{
		auth = GraspAuthenticatedData();
	}

	// DES
	if (scheme == 1)
	{
		// Generate key by random, from screen, or from file
		key_size = DES::DEFAULT_KEYLENGTH;
		GenerateSecByteBlock(key, key_size, L"key", scheme);

		// Generate IV by random, from screen, or from file
		if (mode > 1)
		{
			iv_size = DES::BLOCKSIZE;
			GenerateSecByteBlock(iv, iv_size, L"IV", scheme);

// Write IV to file
#ifdef _WIN32
			StringSource ss_iv(iv, iv.size(), true, new FileSink(".\\Lab 1-2\\des_iv.key"));
#elif __linux__
			StringSource ss_iv(iv, iv.size(), true, new FileSink("./Lab 1-2/des_iv.key"));
#endif
		}

// Write key to file
#ifdef _WIN32
		StringSource ss_key(key, key.size(), true, new FileSink(".\\Lab 1-2\\des_key.key"));
#elif __linux__
		StringSource ss_key(key, key.size(), true, new FileSink("./Lab 1-2/des_key.key"));
#endif

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<DES>::Encryption, ECB_Mode<DES>::Decryption>(key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = Looping_IV<CBC_Mode<DES>::Encryption, CBC_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = Looping_IV<CFB_Mode<DES>::Encryption, CFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = Looping_IV<OFB_Mode<DES>::Encryption, OFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = Looping_IV<CTR_Mode<DES>::Encryption, CTR_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		}
	}
	// AES
	else if (scheme == 2)
	{
		// Select key size from screen
		key_size = SelectKeySize(mode);

		// Validate key's size
		if (key_size == 64 && mode != 6)
		{
			wcout << L"Key size không hợp lệ!" << endl;
			exit(1);
		}

		// Generate key by random, from screen, or from file
		GenerateSecByteBlock(key, key_size, L"key", scheme);

		// Generate IV
		if (mode > 1)
		{
			// Select IV's size
			if (mode == 7 || mode == 8)
			{
				iv_size = SelectIVSize(mode);
			}
			else
			{
				iv_size = AES::BLOCKSIZE;
			}

			// Generate IV by random, from screen, or from file
			GenerateSecByteBlock(iv, iv_size, L"IV", scheme);

			// Write IV to file
#ifdef _WIN32
			StringSource ss_iv(iv, iv.size(), true, new FileSink(".\\Lab 1-2\\aes_iv.key"));
#elif __linux__

			StringSource ss_iv(iv, iv.size(), true, new FileSink("./Lab 1-2/aes_iv.key"));
#endif
		}

// Write key to file
#ifdef _WIN32
		StringSource ss_key(key, key.size(), true, new FileSink(".\\Lab 1-2\\aes_key.key"));
#elif __linux__
		StringSource ss_key(key, key.size(), true, new FileSink("./Lab 1-2/aes_key.key"));
#endif

		// Decide on the mode
		switch (mode)
		{
		case 1:
			etime = Looping_nonIV<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption>(key, plaintext, ciphertext, recoveredtext);
			break;
		case 2:
			etime = Looping_IV<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 3:
			etime = Looping_IV<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 4:
			etime = Looping_IV<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 5:
			etime = Looping_IV<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 6:
			etime = Looping_IV<XTS_Mode<AES>::Encryption, XTS_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recoveredtext);
			break;
		case 7:
			etime = Looping_Authentication<GCM<AES>::Encryption, GCM<AES>::Decryption>(key, iv, plaintext, auth, ciphertext, recoveredtext, recovered_auth);
			break;
		case 8:
			etime = Looping_Authentication<CCM<AES>::Encryption, CCM<AES>::Decryption>(key, iv, plaintext, auth, ciphertext, recoveredtext, recovered_auth);
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

	if (mode > 1)
	{
		wcout << L"IV: ";
		PrettyPrint(iv);
	}

	wcout << L"Ciphertext: ";
	PrettyPrint(ciphertext);

	wcout << L"Recovered text: " << s2ws(recoveredtext) << endl;
	if (mode == 7 || mode == 8)
	{
		wcout << L"Recovered authenticated data: " << s2ws(recovered_auth) << endl;
	}
	wcout << "--------------------------------------------------" << endl;

	wcout << L"Tổng thời gian mã hóa trong 10000 vòng: " << etime[0] << " ms" << endl;
	wcout << L"Thời gian mã hóa trung bình của mỗi vòng: " << etime[0] / 10000 << " ms" << endl;

	wcout << endl;

	wcout << L"Tổng thời gian giải mã trong 10000 vòng: " << etime[1] << " ms" << endl;
	wcout << L"Thời gian giải mã trung bình của mỗi vòng: " << etime[1] / 10000 << " ms" << endl;

	delete[] etime;

	return 0;
}
