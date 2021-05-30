#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include <iostream>
using std::endl;
using std::wcin;
using std::wcout;

#include <fstream>
#include <string>
using std::string;
using std::wstring;
#include <locale>
using std::wstring_convert;

#include <codecvt>
using std::codecvt_utf8;

#include <sstream>
using std::ostringstream;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include <stdexcept>
using std::runtime_error;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/files.h"
using CryptoPP::FileSource;

void SetupVietnameseSupport()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif
}

/* Convert interger to wstring */
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void Save(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
    // http://www.cryptopp.com/docs/ref/class_base64_encoder.html
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}

void SavePrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{

    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadBase64PrivateKey(const string &filename, PrivateKey &key)
{
    throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string &filename, PublicKey &key)
{
    throw runtime_error("Not implemented");
}

void LoadBase64(const string &filename, BufferedTransformation &bt)
{
    throw runtime_error("Not implemented");
}

void PrintKeys(RSA::PrivateKey &privateKey, RSA::PublicKey &publicKey)
{
    wcout << "##### RSA parameters #####" << endl;
    wcout << "Public modulo n = " << integer_to_wstring(publicKey.GetModulus()) << endl;
    wcout << "Public key e = " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
    wcout << "Private prime number p = " << integer_to_wstring(privateKey.GetPrime1()) << endl;
    wcout << "Private prime number q = " << integer_to_wstring(privateKey.GetPrime2()) << endl;
    wcout << "Secret key d = " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
}

char *string_to_ptr_char(string str)
{
    char *c = new char[str.size() + 1];
    for (int i = 0; i < str.size(); ++i)
    {
        c[i] = str[i];
    }
    c[str.size()] = '\0';
    return c;
}

CryptoPP::Integer ReadIntegerFromConsole(wstring string_holder)
{
    wstring wstr_input;
    wcout << string_holder + L": ";
    fflush(stdin);
    getline(wcin, wstr_input);
    char *c = string_to_ptr_char(wstring_to_string(wstr_input));
    CryptoPP::Integer num(c);
    delete[] c;
    return num;
}

string ReadPlaintextFromFile(string filename)
{
    std::ifstream in_file;
    in_file.open(filename);
    if (!in_file.is_open())
    {
        wcout << L"Không thể mở file!" << endl;
        exit(1);
    }

    string data;
    string line;
    while (in_file.good())
    {
        getline(in_file, line);
        data += line;
    }
    in_file.close();
    return data;
}