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


#define USE_AES_NI true


#include <iostream>
#include <array>
#include "Byte.hpp"


#if USE_AES_NI
#include <wmmintrin.h>
#endif


#pragma once


class AES128 {
public:
    static std::array<std::array<byte, 16>, 10> keyExpansion(std::array<byte, 16> oldKey);
    static std::array<byte, 16> encryptBlock(std::array<byte, 16> block, std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule);
    static void test();

    class AESDoesNotWork : public std::exception {};
private:
    static std::array<byte, 16> subBytes(std::array<byte, 16> block);
    static std::array<byte, 16> shiftRows(std::array<byte, 16> block);
    static std::array<byte, 16> mixColumns(std::array<byte, 16> block);
    static std::array<byte, 16> addRoundKey(std::array<byte, 16> block, std::array<byte, 16> key);

    friend class GthCryptor;
};