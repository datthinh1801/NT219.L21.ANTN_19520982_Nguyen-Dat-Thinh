#include <iostream>
#include <vector>
#include "manual_AES_constant.hpp"
using namespace std;

extern const unsigned char gmultab[256][256];
extern const unsigned char sbox[16][16];
extern const unsigned char inv_sbox[16][16];

const unsigned char shift_row_routine[4] = {0, 1, 2, 3};

const unsigned char const_mul_mat[4][4] = {
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2};

const unsigned char const_inv_mul_mat[4][4] = {
    0x0e, 0x0b, 0x0d, 0x09,
    0x09, 0x0e, 0x0b, 0x0d,
    0x0d, 0x09, 0x0e, 0x0b,
    0x0b, 0x0d, 0x09, 0x0e};

void PrintMatrix(const vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < block.size(); ++i)
    {
        for (int j = 0; j < block[i].size(); ++j)
        {
            cout << hex << (unsigned int)block[i][j] << " ";
        }
        cout << endl;
    }
}

vector<vector<unsigned char>> &CircularShiftCol(vector<vector<unsigned char>> &block, unsigned char col)
{
    unsigned char carrier;
    for (int row = 0; row < block.size(); ++row)
    {
        if (row < block.size() - 1)
        {
            if (row == 0)
            {
                carrier = block[row][col];
            }

            block[row][col] = block[row + 1][col];
        }
        else
        {
            block[row][col] = carrier;
        }
    }
    return block;
}

vector<unsigned char> &CircularShiftRow(vector<unsigned char> &row, unsigned char shift_amt)
{
    while (shift_amt--)
    {
        row.push_back(*row.begin());
        row.erase(row.begin());
    }
    return row;
}

unsigned char GFMul(unsigned char w1, unsigned char w2)
{
    return gmultab[w1][w2];
}

// Perform Exclusive-OR on 2 block
// Inputs are 2 blocks of the same size
// Output is a block of the same size
vector<vector<unsigned char>> XOR(const vector<vector<unsigned char>> &block1, const vector<vector<unsigned char>> &block2)
{
    vector<vector<unsigned char>> result(block1.size());
    for (int i = 0; i < result.size(); ++i)
    {
        for (int j = 0; j < block1[i].size(); ++j)
        {
            result[i].push_back(block1[i][j] ^ block2[i][j]);
        }
    }

    return result;
}

// Extract the first 4 bits of a byte and return the decimal value of that 4 bits
unsigned char GetFirst4bitsValue(unsigned char b)
{
    return b >> 4;
}

// Extract the last 4 bits of a byte an return the decimal value of that 4 bits
unsigned char GetLast4bitsValue(unsigned char b)
{
    return b & 15;
}

// Substitute bytes of the block using the S-box
// Input is a 16-byte block
// Output is a 16-byte block
vector<vector<unsigned char>> &SubstituteByte(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            auto row_index = GetFirst4bitsValue(block[i][j]);
            auto col_index = GetLast4bitsValue(block[i][j]);
            block[i][j] = sbox[row_index][col_index];
        }
    }

    return block;
}

// Substitute bytes of the block using the inverse S-box
// Input is a 16-byte block
// Output is a 16-byte block
vector<vector<unsigned char>> &InverseSubstituteByte(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            auto row_index = GetFirst4bitsValue(block[i][j]);
            auto col_index = GetLast4bitsValue(block[i][j]);
            block[i][j] = inv_sbox[row_index][col_index];
        }
    }

    return block;
}

// Shift rows of the block
vector<vector<unsigned char>> &ShiftRows(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        block[i] = CircularShiftRow(block[i], shift_row_routine[i]);
    }
    return block;
}

// Shift rows of the block in the inverse order
vector<vector<unsigned char>> &InverseShiftRows(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        block[i] = CircularShiftRow(block[i], shift_row_routine[(4 - i) % 4]);
    }
    return block;
}

// Mix columns of the state
vector<vector<unsigned char>> MixCols(vector<vector<unsigned char>> &block)
{
    vector<vector<unsigned char>> result(block.size());
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            unsigned char temp = 0;
            for (int k = 0; k < 4; ++k)
            {
                temp ^= GFMul(const_mul_mat[i][k], block[k][j]);
            }
            result[i].push_back(temp);
        }
    }
    return result;
}

// Mix columns of the state in the inverse order
vector<vector<unsigned char>> InverseMixCols(vector<vector<unsigned char>> &block)
{
    vector<vector<unsigned char>> result(block.size());
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            unsigned char temp = 0;
            for (int k = 0; k < 4; ++k)
            {
                temp ^= GFMul(const_inv_mul_mat[i][k], block[k][j]);
            }
            result[i].push_back(temp);
        }
    }
    return result;
}

// Expand the key
// Input is a 16-byte block (key)
// Out put is a 44-byte block (expanded key)
vector<vector<unsigned char>> KeyExpansion(const vector<unsigned char> &key)
{
    vector<vector<unsigned char>> expanded_key(44);
    vector<unsigned char> temp(4);

    // Copy the first 4 words from the orignal key to the expanded key
    // From word 0th to the 3rd word of the key
    for (int i = 0; i < 4; ++i)
    {
        // the word ith of the expanded key comprises of 4 bytes of the corresponding word of the 16-byte key
        // the key is of this format:
        // [byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15, byte16]
    }
}

int main()
{
    vector<vector<unsigned char>> v(4);
    v[0].push_back(0x87);
    v[0].push_back(0xf2);
    v[0].push_back(0x4d);
    v[0].push_back(0x97);

    v[1].push_back(0x6e);
    v[1].push_back(0x4c);
    v[1].push_back(0x90);
    v[1].push_back(0xec);

    v[2].push_back(0x46);
    v[2].push_back(0xe7);
    v[2].push_back(0x4a);
    v[2].push_back(0xc3);

    v[3].push_back(0xa6);
    v[3].push_back(0x8c);
    v[3].push_back(0xd8);
    v[3].push_back(0x95);

    PrintMatrix(v);
    cout << endl;
    auto p = MixCols(v);
    PrintMatrix(p);
    cout << endl;
    auto rev = InverseMixCols(p);
    PrintMatrix(rev);
    return 0;
}