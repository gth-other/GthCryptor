/*
 *  GthCryptor
 *  Copyright (C) 2023 gth-other
 *
 *  GthCryptor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GthCryptor is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GthCryptor.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "SHA256.hpp"


std::vector<byte> SHA256::eval(std::vector<byte> message) {
    uint64_t originalMessageSizeInBits = message.size() * 8;
    message.push_back(0x80);
    while ((message.size() + 8) % 64 != 0) {
        message.push_back(0x00);
    }
    std::array<uint8_t, 8> originalMessageSizeInBitsArray{};
    std::memcpy(originalMessageSizeInBitsArray.data(), &originalMessageSizeInBits, 8);
    for (int32_t i = 8 - 1; i >= 0; i = i - 1) {
        message.push_back(originalMessageSizeInBitsArray[i]);
    }

    std::array<std::array<uint8_t, 4>, 64> words{};
    uint32_t wordJ16, wordJ15, wordJ7, wordJ2, wordJ;
    std::array<uint8_t, 4> word{};
    uint32_t s0, s1;
    uint32_t h0 = 0x6A09E667, h1 = 0xBB67AE85, h2 = 0x3C6EF372, h3 = 0xA54FF53A, h4 = 0x510E527F, h5 = 0x9B05688C, h6 = 0x1F83D9AB, h7 = 0x5BE0CD19;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t ch;
    uint32_t ma;
    uint32_t t1, t2;
    for (uint64_t i = 0; i < message.size(); i = i + 64) {
        for (int32_t j = 0; j < 16; j = j + 1) {
            for (int32_t k = 0; k < 4; k = k + 1) {
                words[j][k] = message[i + j * 4 + k];
            }
        }
        for (int32_t j = 16; j < 64; j = j + 1) {
            wordJ16 = toUInt32(words[j - 16]);
            wordJ15 = toUInt32(words[j - 15]);
            wordJ7 = toUInt32(words[j - 7]);
            wordJ2 = toUInt32(words[j - 2]);
            s0 = rotr(wordJ15, 7) ^ rotr(wordJ15, 18) ^ (wordJ15 >> 3);
            s1 = rotr(wordJ2, 17) ^ rotr(wordJ2, 19) ^ (wordJ2 >> 10);
            wordJ = wordJ16 + s0 + wordJ7 + s1;
            std::memcpy(word.data(), &wordJ, sizeof(wordJ));
            for (int32_t k = 3; k >= 0; k = k - 1) {
                words[j][4 - k - 1] = word[k];
            }
        }
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;
        for (int32_t j = 0; j < 64; j = j + 1) {
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            ch = (e & f) ^ ((~e) & g);
            ma = (a & b) ^ (a & c) ^ (b & c);
            t1 = h + s1 + ch + K[j] + toUInt32(words[j]);
            t2 = s0 + ma;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }

    std::vector<byte> hash;
    hash.reserve(32);
    std::memcpy(word.data(), &h0, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h1, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h2, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h3, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h4, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h5, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h6, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    std::memcpy(word.data(), &h7, 4);
    for (int32_t i = 4 - 1; i >= 0; i = i - 1) {hash.push_back(word[i]);}
    return hash;
}
uint32_t SHA256::rotr(uint32_t a, uint32_t b) {
    return (a >> b) | (a << (4 * 8 - b));
}
uint32_t SHA256::toUInt32(std::array<uint8_t, 4> word) {
    return (uint32_t)word[0] * 16777216 + (uint32_t)word[1] * 65536 + (uint32_t)word[2] * 256 + (int32_t)word[3];
}