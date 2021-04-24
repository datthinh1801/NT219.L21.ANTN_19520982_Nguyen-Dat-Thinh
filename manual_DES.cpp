// Reference: http://web.mit.edu/cfields/info/des/DEShowto.txt
#include <iostream>
#include <cstdlib>
#include <time.h>
#include <string>
#include <vector>
using namespace std;

/*
CONSTANT DECLARATION:
*/

// Permuted choice 1
const unsigned char pc1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};

// Permuted choice 2
const unsigned char pc2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

// Initial permutation
const unsigned char ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

// Expansion
const unsigned char e[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

// Substitution boxes
const unsigned char sbox[8][4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},

    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

// Permutation p
const unsigned char p[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};

// Final Permutation IP**(-1)
const unsigned char inv_ip[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

// Circular shift routine
const unsigned char shift_routine[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Convert a decimal value to a vector of bits
vector<unsigned char> ConvertDecToBin(unsigned char value)
{
    vector<unsigned char> bits(8);
    for (int i = 7; i >= 0; --i)
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

// Generate a key randomly
vector<unsigned char> GenerateKeyRandomly()
{
    vector<unsigned char> key(64);

    // Generate the key
    for (int i = 0; i < 8; ++i)
    {
        // Random an 8-bit number
        unsigned char random_value = rand() % 256;

        // Convert the random number to binary
        vector<unsigned char> bits = ConvertDecToBin(random_value);

        // Assign bits from the random number to the key
        for (int j = 0; j < 8; ++j)
        {
            key[i * 8 + j] = bits[j];
        }
    }

    return key;
}

// Drop parity bits
vector<unsigned char> DropParityBit(vector<unsigned char> block)
{
    // Remove bit from tail to head in order not to confuse the offset while removing
    for (int i = 63; i >= 0; i -= 8)
    {
        block.erase(block.begin() + i);
    }

    return block;
}

// Perform permutation on the 56-bit key
vector<unsigned char> PermutedChoice1(vector<unsigned char> block)
{
    vector<unsigned char> permuted_key(56);
    for (int i = 0; i < 56; ++i)
    {
        permuted_key[i] = block[pc1[i]];
    }
    return permuted_key;
}

// Extract a part of the bits
// Starting from `start`
vector<unsigned char> Split(vector<unsigned char> block, unsigned char start, unsigned char len)
{
    vector<unsigned char> sub_bits(len);
    for (int i = 0; i < len; ++i)
    {
        sub_bits[i] = block[start + i];
    }
    return sub_bits;
}

// Circular left shift the block
vector<unsigned char> CircularLeftShift(vector<unsigned char> block, unsigned char round)
{
    for (int i = 0; i < shift_routine[round - 1]; ++i)
    {
        block.push_back(block[0]);
        block.erase(block.begin());
    }
    return block;
}

// Concate 2 blocks into a single block
// block1|block2
vector<unsigned char> Concate(vector<unsigned char> block1, vector<unsigned char> block2)
{
    vector<unsigned char> block3(block1);
    for (int i = 0; i < block2.size(); ++i)
    {
        block3.push_back(block2[i]);
    }
    return block3;
}

// Perform the permutation choice 2 on the block
vector<unsigned char> PermutedChoice2(vector<unsigned char> block)
{
    vector<unsigned char> result(48);
    for (int i = 0; i < 48; ++i)
    {
        result[i] = block[pc2[i]];
    }
    return result;
}

// Perform initial permutation on the block.
// Input is a 64-bit block.
// Output is a 64-bit block.
vector<unsigned char> IniatialPermutate(vector<unsigned char> block)
{
    vector<unsigned char> result(block.size());
    for (int i = 0; i < block.size(); ++i)
    {
        result[i] = block[ip[i]];
    }
    return result;
}

// Perform expansion on the block.
// Input is a 32-bit block.
// Output is a 48-bit block.
vector<unsigned char> Expand(vector<unsigned char> block)
{
    vector<unsigned char> result(48);
    for (int i = 0; i < 48; ++i)
    {
        result[i] = block[e[i]];
    }
    return result;
}

// Perform Exclusive-or between block1 and block2.
// Inputs are 2 same-size blocks.
// Output is a XORed block with the same size as inputs.
vector<unsigned char> XOR(vector<unsigned char> block1, vector<unsigned char> block2)
{
    vector<unsigned char> result(block1.size());
    for (int i = 0; i < result.size(); ++i)
    {
        result[i] = block1[i] ^ block2[i];
    }
    return result;
}

int main()
{
    // Seed the random function
    srand(time(0));
    cout << hex << 250 << endl;
    return 0;
}