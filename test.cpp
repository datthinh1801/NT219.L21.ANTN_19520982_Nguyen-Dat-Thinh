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

vector<unsigned char> Split(vector<unsigned char> block, unsigned int start, unsigned char len)
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

// Fine
vector<unsigned char> ConvertStringToBin(string str)
{
    vector<unsigned char> result;
    for (int i = 0; i < str.length(); ++i)
    {
        vector<unsigned char> single_char = ConvertDecToBin(str[i], 8);

        for (int j = 0; j < single_char.size(); ++j)
        {
            result.push_back(single_char[j]);
        }
    }

    return result;
}

int main()
{
    string s = "mot hai ba bon nam sau bay tam chin";
    auto block = ConvertStringToBin(s);
    for (int i = 0; i < block.size(); ++i)
    {
        if (i % 8 == 0)
        {
            cout << endl;
            system("pause");
            // Bug
            cout << "#" << i << ":\n";
            auto subb = Split(block, i, 8);
            printBits(subb);
        }

        cout << (unsigned int)block[i] << " ";
    }
    // string r = ConvertBinToString(block);
    // cout << "result: " << r << endl;
    return 0;
}