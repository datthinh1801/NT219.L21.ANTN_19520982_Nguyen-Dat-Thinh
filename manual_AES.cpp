#include <iostream>
#include <vector>
#include <time.h>
#include <string>
#include <iomanip>
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

const unsigned char round_constants[4][10] = {
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

// Convert a string to a 4xN matrix represent its hexadecimal values
// The output might not be of 4xN in shape
// Invoke the AddPadding function to mitigate this.
vector<vector<unsigned char>> ConvertStringToBlock(string str)
{
    vector<vector<unsigned char>> block(4);
    int cur_row = 0;

    for (unsigned char c : str)
    {
        block[cur_row].push_back(c);
        cur_row = (cur_row + 1) % 4;
    }

    return block;
}

// Convert a matrix of hexadecimal values to a string
// The input block should be stripped paddings.
string ConvertBlockToString(const vector<vector<unsigned char>> &block)
{
    string result = "";
    for (int i = 0; i < block[0].size(); ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            result += block[j][i];
        }
    }
    return result;
}

void PrintMatrix(const vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < block.size(); ++i)
    {
        for (int j = 0; j < block[i].size(); ++j)
        {
            cout << setfill('0') << setw(2) << hex << uppercase << (unsigned int)block[i][j] << " ";
        }
        cout << endl;
    }
}

// Rotate a word circularly
// This word is the first word of the block which is passed to the function
vector<vector<unsigned char>> &RotWord(vector<vector<unsigned char>> &block)
{
    unsigned char carrier;
    for (int row = 0; row < block.size(); ++row)
    {
        if (row < block.size() - 1)
        {
            if (row == 0)
            {
                carrier = block[row][0];
            }

            block[row][0] = block[row + 1][0];
        }
        else
        {
            block[row][0] = carrier;
        }
    }
    return block;
}

// Shift a row circularly for `shift_amt` times
vector<unsigned char> &CircularShiftRow(vector<unsigned char> &row, unsigned char shift_amt)
{
    while (shift_amt--)
    {
        row.push_back(*row.begin());
        row.erase(row.begin());
    }
    return row;
}

// Multiply 2 bytes on the GF(256)
// This is a helper function for the readability purpose
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

// Randomly generate a 16-byte key
vector<vector<unsigned char>> RandomKey()
{
    srand(time(0));

    vector<vector<unsigned char>> key(4);
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            key[i].push_back(rand() % 256);
        }
    }
    return key;
}

// Extract a 16-byte block from the block
// The splitted block comes from the start-th word to the next 3 words of the block
// [NOTE] The block is major-column
vector<vector<unsigned char>> Split(const vector<vector<unsigned char>> &block, unsigned int start)
{
    vector<vector<unsigned char>> sub_block(4);
    for (int j = 0; j < 4; ++j)
    {
        for (int i = 0; i < 4; ++i)
        {
            sub_block[i].push_back(block[i][start + j]);
        }
    }
    return sub_block;
}

// Add NULL padding the block if its size is not of a product of 16
vector<vector<unsigned char>> &AddPadding(vector<vector<unsigned char>> &block)
{
    // Add padding if there is an incomplete word
    int max_size = max(max(block[0].size(), block[1].size()), max(block[2].size(), block[3].size()));
    for (int i = 0; i < 4; ++i)
    {
        while (block[i].size() < max_size)
        {
            block[i].push_back(0);
        }
    }

    // while the block size is not a product of 16
    while (block[0].size() % 4 > 0)
    {
        // Add NULL padding
        for (int i = 0; i < 4; ++i)
        {
            block[i].push_back(0x0);
        }
    }

    return block;
}

// Remove NULL padding from the block
vector<vector<unsigned char>> &RemovePadding(vector<vector<unsigned char>> &block)
{
    int bound = 3;
    int cur_row = 3;
    while (bound > -1)
    {
        if (block[cur_row].back() == 0)
        {
            block[cur_row].pop_back();
        }
        else
        {
            bound = cur_row - 1;
        }
        cur_row = ((cur_row - 1) + 4) % 4;
    }
    return block;
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
// Input is a 4-word block (key)
// Out put is a 44-word block (expanded key)
vector<vector<unsigned char>> KeyExpansion(const vector<vector<unsigned char>> &key)
{
    // Initialize the expanded key with the first 4 words from the 16-byte key
    vector<vector<unsigned char>> expanded_key(key);
    vector<vector<unsigned char>> temp(4);

    for (int i = 4; i < 44; ++i)
    {
        temp.clear();

        // Extract the last word of the expanded_key
        // temp = w[i - 1]
        for (int j = 0; j < 4; ++j)
        {
            temp[j].push_back(expanded_key[j].back());
        }

        if (i % 4 == 0)
        {
            // temp = SubWord(RotWord(temp)) ^ Rcon[i / 4]
            temp = SubstituteByte(RotWord(temp));
            for (int j = 0; j < 4; ++j)
            {
                temp[j].back() ^= round_constants[j][(i / 4) - 1];
            }
        }

        // w[i] = w[i - 4] ^ temp
        for (int j = 0; j < 4; ++j)
        {
            expanded_key[j].push_back(expanded_key[j][i - 4] ^ temp[j][0]);
        }
    }

    return expanded_key;
}

vector<vector<unsigned char>> Encrypt(string plaintext, const vector<vector<unsigned char>> &key)
{
    vector<vector<unsigned char>> cipher_block(4);
    auto plain_block = ConvertStringToBlock(plaintext);

    // Add padding
    plain_block = AddPadding(plain_block);

    // [KEY EXPANSION]
    auto expanded_key = KeyExpansion(key);

    // Loop through 4 words of the plain_block at a time
    for (int i = 0; i < plain_block[0].size(); i += 4)
    {
        // Extract a 4-word block from the original block
        auto current_state = Split(plain_block, i);
        // Extract the round key 0
        auto round_key_0 = Split(expanded_key, 0);

        // [Initial transformation]
        current_state = XOR(current_state, round_key_0);

        // Loop through 10 rounds
        for (int round = 1; round <= 10; ++round)
        {
            // [SUB BYTES]
            current_state = SubstituteByte(current_state);

            // [SHIFT ROWS]
            current_state = ShiftRows(current_state);

            // Round 10 does not have this step
            if (round < 10)
            {
                // [MIX COLUMNS]
                current_state = MixCols(current_state);
            }

            // [ADD ROUND KEY]
            auto round_key = Split(expanded_key, round * 4);
            current_state = XOR(current_state, round_key);
        }

        // Append the state to the overall cipher_block
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                cipher_block[i].push_back(current_state[i][j]);
            }
        }
    }
    return cipher_block;
}

string Decrypt(const vector<vector<unsigned char>> &cipher_block, const vector<vector<unsigned char>> &key)
{
    vector<vector<unsigned char>> plain_block(4);

    // [KEY EXPANSION]
    auto expanded_key = KeyExpansion(key);

    // Loop through 4 words of the cipher_block at a time
    for (int i = 0; i < cipher_block[0].size(); i += 4)
    {
        // Extract a 4-word block from the original block
        auto current_state = Split(cipher_block, i);
        // Extract the round key 0
        auto round_key_10 = Split(expanded_key, 40);

        // [Initial transformation]
        current_state = XOR(current_state, round_key_10);

        // Loop through 10 rounds
        for (int round = 9; round >= 0; --round)
        {
            // [INVERSE SHIFT ROWS]
            current_state = InverseShiftRows(current_state);
            // [INVERSE SUB BYTES]
            current_state = InverseSubstituteByte(current_state);
            // [ADD ROUND KEY]
            auto round_key = Split(expanded_key, round * 4);
            current_state = XOR(current_state, round_key);

            if (round > 0)
            {
                // [INVERSE MIX COLUMNS]
                current_state = InverseMixCols(current_state);
            }
        }

        // Append the state to the overall plain_block
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                plain_block[i].push_back(current_state[i][j]);
            }
        }
    }
    plain_block = RemovePadding(plain_block);
    return ConvertBlockToString(plain_block);
}

int main()
{
    string plaintext;
    std::cout << "Plaintext: ";
    getline(cin, plaintext);

    auto key = RandomKey();
    std::cout << "Key:\n";
    PrintMatrix(key);
    std::cout << endl;

    auto cipher_block = Encrypt(plaintext, key);
    std::cout << "Cipher block:\n";
    PrintMatrix(cipher_block);
    std::cout << endl;

    auto recovered_string = Decrypt(cipher_block, key);
    std::cout << "Recovered: " << recovered_string << endl;
    return 0;
}