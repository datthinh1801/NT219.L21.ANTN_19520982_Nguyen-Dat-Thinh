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
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include <cryptopp/hex.h>
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

    char sep;
#ifdef _WIN32
    sep = '\\';
#elif __linux__
    sep = '/'
#endif

    string filename = '.' + sep + "Lab 5-6" + sep;
    filename += "plaintext.txt";

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

// Hash function
template <class HASH>
string hash_function(string message)
{
}

int main(int argc, char *argv[])
{
    CryptoPP::SHA3_512 hash;
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << hash.DigestSize() << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;
    wstring message;
    wcout << "Please input message" << endl;
    getline(wcin, message);

    // Compute digest
    string digest;
    hash.Restart();
    hash.Update((const CryptoPP::byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((CryptoPP::byte *)&digest[0], digest.size());

    // Pretty print digest
    wcout << "Message: " << message << endl;
    PrettyPrint(digest);
    return 0;
}
