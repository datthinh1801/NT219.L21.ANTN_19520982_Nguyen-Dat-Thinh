#include <string>
#include <iostream>
using namespace std;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/shake.h"

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/files.h>
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#define N_ITER 10000

// Convert string to wstring
wstring s2ws(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

// Convert wstring to string
string ws2s(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

// Vietnamese configuration
void SetupVietnameseSupport()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
}

// Pretty print digest as a hex string
void PrettyPrint(const string &digest)
{
    string encode;
    encode.clear();
    StringSource(digest, true,
                 new HexEncoder(new StringSink(encode)));
    wcout << "Digest: " << s2ws(encode) << endl;
}

// Read (Vietnamese) message from a given file
string ReadMessageFromFile(string filename)
{
    std::locale loc(std::locale(), new codecvt_utf8<wchar_t>);
    std::wifstream in_file;
    in_file.open(filename);
    if (!in_file.is_open())
    {
        wcout << L"Không thể mở file!" << endl;
        exit(1);
    }

    in_file.imbue(loc);
    wstring data;
    wstring line;
    while (in_file.good())
    {
        getline(in_file, line);
        data += line + L'\n';
    }
    in_file.close();
    wcout << "Plaintext: " << data << endl;
    return ws2s(data);
}

// Read (Vietnamese) message from console
string ReadMessageFromConsole()
{
    wstring winput;
    wcout << L"Plaintext: ";
    fflush(stdin);
    getline(wcin, winput);
    return ws2s(winput);
}

// Select the source of message
int SelectMessageSource()
{
    wcout << L"Bạn muốn nhập message từ đâu?" << endl;
    wcout << L"(1) File" << endl;
    wcout << L"(2) Console" << endl;
    wcout << L"> ";

    int option;

    try
    {
        wcin >> option;
        return option;
    }
    catch (exception &e)
    {
        wcout << L"Đã xảy ra lỗi trong quá trình đọc plaintext." << endl;
        wcout << e.what() << endl;
        exit(1);
    }
}

// Get the message from either a file or the console
string AcquireMessage()
{
    int option = SelectMessageSource();

    string sep;
#ifdef _WIN32
    sep = "\\";
#elif __linux__
    sep = "/"
#endif

    string filename = "." + sep + "Lab 5-6" + sep;
    filename += "message.txt";

    switch (option)
    {
    case 1:
        return ReadMessageFromFile(filename);
    case 2:
        return ReadMessageFromConsole();
    default:
        wcout << L"Lựa chọn không hợp lệ!" << endl;
        exit(1);
    }
}

// HASH FUNCTIONS
// Compute and return digest of a given message
template <class HASH>
string Hash(const string &message)
{
    HASH hash;
    // wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    // wcout << "Digest size: " << hash.DigestSize() << endl;
    // wcout << "Block size: " << hash.BlockSize() << endl;

    // Compute digest
    string digest;
    hash.Restart();
    hash.Update((const CryptoPP::byte *)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((CryptoPP::byte *)&digest[0], digest.size());
    return digest;
}

template <class SHAKE>
string HashXOF(const string &message, int digest_size)
{
    SHAKE hash;

    // Compute digest
    string digest;
    hash.Restart();
    hash.Update((const CryptoPP::byte *)message.data(), message.size());
    digest.resize(digest_size);
    hash.TruncatedFinal((CryptoPP::byte *)&digest[0], digest.size());
    return digest;
}

template <class HASH>
double LoopingHash(const string &message, string &digest)
{
    double etime = 0;
    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        digest = Hash<HASH>(message);
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }
    return etime;
}

template <class SHAKE>
double LoopingHashXOF(const string &message, string &digest, int digest_size)
{
    double etime = 0;
    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        digest = HashXOF<SHAKE>(message, digest_size);
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }
    return etime;
}

int SelectHashFunction()
{
    wcout << L"Chọn hàm hash:" << endl;
    wcout << "(1) SHA224" << endl;
    wcout << "(2) SHA256" << endl;
    wcout << "(3) SHA384" << endl;
    wcout << "(4) SHA512" << endl;
    wcout << "(5) SHA3-224" << endl;
    wcout << "(6) SHA3-256" << endl;
    wcout << "(7) SHA3-384" << endl;
    wcout << "(8) SHA3-512" << endl;
    wcout << "(9) SHAKE128" << endl;
    wcout << "(10) SHAKE256" << endl;
    wcout << "> ";

    int option;
    try
    {
        wcin >> option;
        return option;
    }
    catch (exception &e)
    {
        wcout << L"Lỗi xảy ra khi chọn hàm hash!" << endl;
        wcout << e.what() << endl;
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    SetupVietnameseSupport();

    // Acquire message
    string message = AcquireMessage();
    string digest;

    // Selet hash function
    int option = SelectHashFunction();
    double etime;
    int digest_size;

    if (option == 10 || option == 9)
    {
        wcout << "Digest size: ";
        wcin >> digest_size;
    }

    switch (option)
    {
    case 1:
        etime = LoopingHash<CryptoPP::SHA224>(message, digest);
        break;
    case 2:
        etime = LoopingHash<CryptoPP::SHA256>(message, digest);
        break;
    case 3:
        etime = LoopingHash<CryptoPP::SHA384>(message, digest);
        break;
    case 4:
        etime = LoopingHash<CryptoPP::SHA512>(message, digest);
        break;
    case 5:
        etime = LoopingHash<CryptoPP::SHA3_224>(message, digest);
        break;
    case 6:
        etime = LoopingHash<CryptoPP::SHA3_256>(message, digest);
        break;
    case 7:
        etime = LoopingHash<CryptoPP::SHA3_384>(message, digest);
        break;
    case 8:
        etime = LoopingHash<CryptoPP::SHA3_512>(message, digest);
        break;
    case 9:
        etime = LoopingHashXOF<CryptoPP::SHAKE128>(message, digest, digest_size);
        break;
    case 10:
        etime = LoopingHashXOF<CryptoPP::SHAKE256>(message, digest, digest_size);
        break;
    default:
        wcout << L"Lựa chọn không hợp lệ!" << endl;
        exit(1);
    }

    wcout << "Message: " << s2ws(message) << endl;
    wcout << "Digest: ";
    PrettyPrint(digest);
    wcout << "Execution time: " << etime * 1000 / N_ITER << " ms." << endl;
    return 0;
}
