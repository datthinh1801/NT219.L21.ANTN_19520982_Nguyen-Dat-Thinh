#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/queue.h> // using for load functions
using CryptoPP::ByteQueue;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation; // using for load function
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/nbtheory.h"
#include "cryptopp/modarith.h"
#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include <iomanip>

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <assert.h>
#include "helper.cpp"
using namespace helper;

#define N_ITER 10000

string RSA_Encrypt(AutoSeededRandomPool &rng, const RSA::PublicKey &rsaPublicKey, const string &plaintext)
{
    string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);
    StringSource(plaintext, true,
                 new PK_EncryptorFilter(rng, encryptor,
                                        new StringSink(ciphertext)));
    return ciphertext;
}

string RSA_Decrypt(AutoSeededRandomPool &rng, const RSA::PrivateKey &rsaPrivateKey, const string &ciphertext)
{
    string recovered_text;
    RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
    StringSource(ciphertext, true,
                 new PK_DecryptorFilter(rng, decryptor,
                                        new StringSink(recovered_text)));
    return recovered_text;
}

void PrettyPrint(string str)
{
    string encoded;
    encoded.clear();
    StringSource(str, true,
                 new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded);
}

string DecodeCiphertext(const wstring &wciphertext)
{
    string ciphertext;
    StringSource(wstring_to_string(wciphertext), true,
                 new HexDecoder(new StringSink(ciphertext)));
    return ciphertext;
}

void GenerateKeysRandomly(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey, int key_size)
{
    AutoSeededRandomPool rng;
    rsaPrivateKey.GenerateRandomWithKeySize(rng, key_size);
    rsaPublicKey = RSA::PublicKey(rsaPrivateKey);
}

void LoadKeysFromFiles(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
    try
    {
        AutoSeededRandomPool rng;
#ifdef _WIN32
        LoadPublicKey(".\\Lab 3-4\\rsa-public.key", rsaPublicKey);
        LoadPrivateKey(".\\Lab 3-4\\rsa-private.key", rsaPrivateKey);
#elif __linux__
        LoadPublicKey("./Lab 3-4/rsa-public.key", rsaPublicKey);
        LoadPrivateKey("./Lab 3-4/rsa-private.key", rsaPrivateKey);
#endif

        if (!rsaPrivateKey.Validate(rng, 3))
        {
            throw runtime_error("RSA private key validation failed.");
        }
        if (!rsaPublicKey.Validate(rng, 3))
        {
            throw runtime_error("RSA public key validation failed.");
        }
    }
    catch (CryptoPP::Exception &e)
    {
        wcout << "Exception on reading keys from files: " << e.what() << endl;
        exit(1);
    }
}

void GetKeyFromConsole(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
    wstring wstr_prime_p, wstr_prime_q, wstr_private_exp, wstr_public_exp;

    // Get modulo n
    Integer n = ReadIntegerFromConsole(L"Modulo n");
    rsaPrivateKey.SetModulus(n);

    // Get prime p
    Integer p = ReadIntegerFromConsole(L"Prime p");
    rsaPrivateKey.SetPrime1(p);

    // Get prime q
    Integer q = ReadIntegerFromConsole(L"Prime q");
    rsaPrivateKey.SetPrime2(q);

    // Get public exponential
    Integer e = ReadIntegerFromConsole(L"Public exponential e");
    rsaPrivateKey.SetPublicExponent(e);

    // Get private exponential
    Integer d = ReadIntegerFromConsole(L"Private exponential d");
    rsaPrivateKey.SetPrivateExponent(d);

    // https://stackoverflow.com/questions/23878893/why-does-this-throw-cryptomaterial-this-object-contains-invalid-values-in-c
    rsaPrivateKey.SetModPrime1PrivateExponent(d % (p - 1));
    rsaPrivateKey.SetModPrime2PrivateExponent(d % (q - 1));
    rsaPrivateKey.SetMultiplicativeInverseOfPrime2ModPrime1(q.InverseMod(p));

    // Generate public key from the given private key
    rsaPublicKey = RSA::PublicKey(rsaPrivateKey);
}

void GetDefaultKey(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
    Integer n("3094342908147763265590132917572861112257549816812479067601342865572889463289538257247593117370325293671119369173971986423507336456732032972709068500292121699523269209494382227759250496533363019948600531748288470312209930571295538470592342639324144825782946516054208698359346263814786690547035723084124072998512707954186806748239631423700541521042342254469633139373379451028788081026596856503260342125446971303480711513676222484647271202365554164437636849626816058357173789943433543782101098873505528660705086582348885285108979966471162212821617885029202225791420722437712127343998979641827704841989418050846531570190643042130078888089899962698928805899860314219433648540823838126392734130750786217693908357564796054125208637900868904995133597700842906041852469026705837059852412401640420144736573775893395655905131985917693004183530710384179756293264662014253291089968196788450497825826240042357555084494195971554581191153369.");
    Integer p("1760307012405166607648281054357973805201847707677833046009507921450573521399234693264912873612346556842132931571737717174938484296856606155312711721418613717869724955110643271900864968025702149151503612290135965228477668354433942834112938729626371824862008751043718783099754095524991510290423356974241441865858799864945321972061200688446441466127822056859748897659752515906852388473566623134227053509212680689183381933609267000225358128417607100014479949489904379.");
    Integer q("1757842743533617239498600533345498045774787945184480118901181551960888931411344988365384306906857902439663554061502259040449412905184641366189278162142052276546603016525045742760639542054940136128304615935201802291219861422514706407868052620749392329742726577908925599370711789138405455054306972360051747638023717045242865478691561461543256892478586053641510025581042026842956035197836291746930000120797112890692029760146445737826040642970922391670932315893738811.");
    Integer e("17.");
    Integer d("30336695177919247701864048211498638355466174674632147721581792799734210424407237816152873699709071506579601658568352808073601337811098362477539887257765899014934011857788061056463240162091794313221573840669494806982450299718583710496003359209060243390028887412296163709405355527595947946539565912589451696063850077982223595570976778663730799225905316220290520974248818147341059617907812318659415118876931091210595210918394338084777168650642687886643498525753098576853176803967153888580583442843467428275190526667016866415877515245183425512175845634627663790068249418051240138274732982881671596085704868126045568720829888488255953454910640207788418875074265043247111992186826651263362325314721021928456450801967073033234114561338102299306362101018407463838462105230552286052308845229931072470337488099951343622519818477046762386166548633095647891081860596639212363531123695225870628138367666578027291136908865550414860857943.");

    rsaPrivateKey.SetModulus(n);
    rsaPrivateKey.SetPrime1(p);
    rsaPrivateKey.SetPrime2(q);
    rsaPrivateKey.SetPublicExponent(e);
    rsaPrivateKey.SetPrivateExponent(d);
    rsaPrivateKey.SetModPrime1PrivateExponent(d % (p - 1));
    rsaPrivateKey.SetModPrime2PrivateExponent(d % (q - 1));
    rsaPrivateKey.SetMultiplicativeInverseOfPrime2ModPrime1(q.InverseMod(p));

    rsaPublicKey = RSA::PublicKey(rsaPrivateKey);
}

void ShowMainMenu()
{
    wcout << L"Bạn muốn làm gì?" << endl;
    wcout << L"(1) Encrypt" << endl;
    wcout << L"(2) Decrypt" << endl;
    wcout << L"(3) Computation on Zp" << endl;
    wcout << L"> ";
}

void ShowKeyMenu()
{
    wcout << L"Bạn muốn nhập key từ đâu?" << endl;
    wcout << L"(1) Default value from code" << endl;
    wcout << L"(2) Random" << endl;
    wcout << L"(3) File" << endl;
    wcout << L"(4) Console" << endl;
    wcout << L"> ";
}

void ShowDataMenu(wstring what)
{
    wcout << L"Bạn muốn nhập " + what << L" từ đâu?" << endl;
    wcout << L"(1) File" << endl;
    wcout << L"(2) Console" << endl;
    wcout << L"> ";
}

void GetKey(RSA::PrivateKey &privateKey, RSA::PublicKey &publicKey)
{
    // Select key source
    ShowKeyMenu();
    int option;
    try
    {
        wcin >> option;
    }
    catch (exception e)
    {
        wcout << "Exception on reading key source option: " << e.what() << endl;
        exit(1);
    }

    // Generate key based on selection
    switch (option)
    {
    case 1:
        GetDefaultKey(privateKey, publicKey);
        break;
    case 2:
        GenerateKeysRandomly(privateKey, publicKey, 3072);
        break;
    case 3:
        LoadKeysFromFiles(privateKey, publicKey);
        break;
    case 4:
        GetKeyFromConsole(privateKey, publicKey);
        break;
    default:
        wcout << L"Lựa chọn không hợp lệ!" << endl;
        exit(1);
    }
}

void Encrypt()
{
    // Generate keys
    AutoSeededRandomPool rng;

    // Generate keys
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    GetKey(privateKey, publicKey);
    PrintKeys(privateKey, publicKey);
    wcout << endl;

    // Grasp plaintext
    ShowDataMenu(L"plaintext");
    int option;
    try
    {
        wcin >> option;
    }
    catch (exception e)
    {
        wcout << "Exception on reading plaintext source option: " << e.what() << endl;
        exit(1);
    }

    string plaintext;
    wstring wplaintext;
    switch (option)
    {
    case 1:
#ifdef _WIN32
        plaintext = ReadPlaintextFromFile(".\\Lab 3-4\\plaintext.txt");
#elif __linux__
        plaintext = ReadPlaintextFromFile("./Lab 3-4/plaintext.txt");
#endif
        break;
    case 2:
        wcout << L"Nhập plaintext: ";
        fflush(stdin);
        getline(wcin, wplaintext);
        plaintext = wstring_to_string(wplaintext);
        break;
    default:
        wcout << L"Lựa chọn không hợp lệ!" << endl;
        exit(1);
    }

    // Encryption
    string ciphertext;
    double etime = 0;
    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        ciphertext = RSA_Encrypt(rng, publicKey, plaintext);
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }

    wcout << "Ciphertext: ";
    PrettyPrint(ciphertext);
    wcout << endl;
    wcout << "Average encryption time: " << 1000 * etime / N_ITER << " ms." << endl;
}

void Decrypt()
{
    // Generate keys
    AutoSeededRandomPool rng;

    // Generate keys
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    GetKey(privateKey, publicKey);
    PrintKeys(privateKey, publicKey);
    wcout << endl;

    // Grasp ciphertext
    ShowDataMenu(L"ciphertext");
    int option;
    try
    {
        wcin >> option;
    }
    catch (exception e)
    {
        wcout << "Exception on reading ciphertext source option: " << e.what() << endl;
        exit(1);
    }

    string ciphertext;
    wstring wciphertext;
    switch (option)
    {
    case 1:
#ifdef _WIN32
        ciphertext = ReadCiphertextFromFile(".\\Lab 3-4\\ciphertext.txt");
#elif __linux__
        ciphertext = ReadCiphertextFromFile("./Lab 3-4/ciphertext.txt");
#endif
        break;
    case 2:
        wcout << L"Nhập ciphertext: ";
        fflush(stdin);
        getline(wcin, wciphertext);

        if (wciphertext[wciphertext.size() - 1] != L'H')
        {
            wciphertext += L'H';
        }
        ciphertext = DecodeCiphertext(wciphertext);
    }

    // Decryption
    string recovered_text;
    double etime = 0;
    for (int i = 0; i < N_ITER; ++i)
    {
        int start = clock();
        recovered_text = RSA_Decrypt(rng, privateKey, ciphertext);
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }

    wcout << "Recovered text: " << string_to_wstring(recovered_text) << endl;
    wcout << "Average decryption time: " << 1000 * etime / N_ITER << " ms." << endl;
}

void PerformZpComputation()
{
    Integer x = ReadIntegerFromConsole(L"x");
    Integer y = ReadIntegerFromConsole(L"y");
    Integer z = ReadIntegerFromConsole(L"z");
    Integer result;

    wcout << "x + y = ";
    result = x + y;
    wcout << integer_to_wstring(result) << endl;

    wcout << "x - y = ";
    result = x - y;
    wcout << integer_to_wstring(result) << endl;

    wcout << "(x * y) mod z = ";
    result = a_times_b_mod_c(x, y, z);
    wcout << integer_to_wstring(result) << endl;

    wcout << "(x ^ y) mod z = ";
    result = a_exp_b_mod_c(x, y, z);
    wcout << integer_to_wstring(result) << endl;
}

int main(int argc, char *argv[])
{
    try
    {
        SetupVietnameseSupport();

        ShowMainMenu();
        int option;
        try
        {
            wcin >> option;
        }
        catch (exception e)
        {
            wcout << "Exception on reading operation option: " << e.what() << endl;
            exit(1);
        }

        switch (option)
        {
        case 1:
            Encrypt();
            break;
        case 2:
            Decrypt();
            break;
        case 3:
            PerformZpComputation();
            break;
        default:
            wcout << L"Lựa chọn không hợp lệ!" << endl;
            exit(1);
        }
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Exception in main(): " << e.what() << endl;
    }

    return 0;
}
