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


#include "AES128.hpp"
#include "UInt128.hpp"
#include "SHA256.hpp"


#pragma once


class GthCryptor {
public:
    static std::array<byte, 16> generateKeyFromPassword(const std::string &password, int32_t iterations);
    static std::array<byte, 16> generateRandomKey();
    static void encryptFile(const std::string &inputPath, const std::string &outputPath, std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule);
    static void decryptFile(const std::string &inputPath, const std::string &outputPath, std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule);

    class InvalidNumberOfIterations : public std::exception {};
    class NoEntropySource : public std::exception {};
    class NoInputFile : public std::exception {};
    class NoOutputFile : public std::exception {};
    class InvalidKey : public std::exception {};
private:
    static std::pair<std::array<byte, 16>, int32_t> readBlock(std::ifstream &input);
    static void writeBlock(std::ofstream &output, std::array<byte, 16> block, int32_t extraBytes=0);
    static std::array<byte, 16> getKCVBlock(std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule);
    static uint64_t getFileSize(const std::string &path);
};