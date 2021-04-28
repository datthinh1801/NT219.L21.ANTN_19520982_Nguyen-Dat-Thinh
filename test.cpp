#include <iostream>
#include <vector>
#include <string>
#include <time.h>
#include <cstdlib>
using namespace std;

void printBits(vector<unsigned char> block)
{
    for (int i = 0; i < block.size(); ++i)
    {
        cout << (unsigned int)block[i] << " ";
    }
    cout << endl;
}

vector<unsigned char> Split(vector<unsigned char> block, unsigned char start, unsigned char len)
{
    vector<unsigned char> sub_bits(len);
    for (int i = 0; i < len; ++i)
    {
        sub_bits[i] = block[start + i];
    }

    return sub_bits;
}

vector<unsigned char> ConvertDecToBin(unsigned char value, unsigned char len)
{
    vector<unsigned char> bits(len);
    for (int i = len - 1; i >= 0; --i)
    {
        bits[i] = value & 1;
        value >>= 1;
    }

    return bits;
}

unsigned char ConvertBinToDec(vector<unsigned char> block)
{
    unsigned char result = 0;
    for (int i = 0; i < block.size(); ++i)
    {
        result = (result << 1) + block[i];
    }
    return result;
}

vector<unsigned char> ConvertStringToBin(string str)
{
    vector<unsigned char> result;
    for (int i = 0; i < str.length(); ++i)
    {
        vector<unsigned char> single_char = ConvertDecToBin(int(str[i]), 8);
        for (int j = 0; j < 8; ++j)
        {
            result.push_back(single_char[j]);
        }
    }

    return result;
}

string ConvertBinToString(vector<unsigned char> block)
{
    string result = "";
    for (int i = 0; i < block.size(); i += 8)
    {
        vector<unsigned char> sub_block = Split(block, i, 8);
        unsigned char ascii_value = ConvertBinToDec(sub_block);
        result += ascii_value;
    }
    return result;
}

vector<unsigned char> GenerateKeyRandomly()
{
    vector<unsigned char> key(64);

    // Generate the key
    for (int i = 0; i < 8; ++i)
    {
        // Random an 8-bit number
        unsigned char random_value = rand() % 256;

        // Convert the random number to binary
        vector<unsigned char> bits = ConvertDecToBin(random_value, 8);

        // Assign bits from the random number to the key
        for (int j = 0; j < 8; ++j)
        {
            key[i * 8 + j] = bits[j];
        }
    }

    return key;
}

vector<unsigned char> DropParityBit(vector<unsigned char> block)
{
    // Remove bit from tail to head in order not to confuse the offset while removing
    for (int i = 63; i >= 0; i -= 8)
    {
        block.erase(block.begin() + i);
    }

    return block;
}

vector<unsigned char> PermutedChoice1(vector<unsigned char> block)
{
    const unsigned char pc1[56] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4};

    vector<unsigned char> permuted_key(56);
    for (int i = 0; i < 56; ++i)
    {
        permuted_key[i] = block[pc1[i]];
    }
    return permuted_key;
}

int main()
{
    srand(time(0));
    auto key = GenerateKeyRandomly();
    cout << key.size() << endl;
    // auto dropped_key = DropParityBit(key);
    // cout << dropped_key.size() << endl;
    auto pc1_key = PermutedChoice1(key);
    printBits(pc1_key);
    return 0;
}