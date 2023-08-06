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


#include "GthCryptor.hpp"


std::array<byte, 16> GthCryptor::generateKeyFromPassword(const std::string &password, int32_t iterations) {
    if (iterations < 1) {
        throw InvalidNumberOfIterations();
    }

    std::vector<byte> passwordVector;
    passwordVector.insert(passwordVector.begin(), password.begin(), password.end());

    std::vector<byte> hash = SHA256::eval(passwordVector);
    for (int32_t i = 0; i < iterations - 1; i = i + 1) {
        hash = SHA256::eval(hash);
    }

    std::array<byte, 16> key{};
    for (int32_t i = 0; i < 16; i = i + 1) {
        key[i] = hash[i];
    }

    return key;
}
std::array<byte, 16> GthCryptor::generateRandomKey() {
    std::ifstream source;
    source.open("/dev/random");
    if (!source.is_open()) {
        throw NoEntropySource();
    }

    std::array<byte, 16> key{};
    for (int32_t i = 0; i < 16; i = i + 1) {
        key[i] = source.get();
    }

    source.close();

    return key;
}
void GthCryptor::encryptFile(const std::string &inputPath, const std::string &outputPath, std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule) {
    AES128::test();

    std::ifstream input;
    input.open(inputPath);
    if (!input.is_open()) {
        throw NoInputFile();
    }

    std::ofstream output;
    output.open(outputPath);
    if (!output.is_open()) {
        throw NoOutputFile();
    }

    UInt128 ctr;
    ctr.setSmallSecureRandomValue();
    writeBlock(output, ctr.getBlock());

    writeBlock(output, getKCVBlock(key, keySchedule));

    bool finish = false;
    for (uint64_t i = 1; true; i = i + 1) {
        std::pair<std::array<byte, 16>, int32_t> blockInfo = readBlock(input);
        if (blockInfo.second < 16) {
            blockInfo.first[blockInfo.second] = 0x01;
            for (int32_t j = blockInfo.second + 1; j < 16; j = j + 1) {
                blockInfo.first[j] = 0x00;
            }
            finish = true;
        }
        blockInfo.first = AES128::addRoundKey(blockInfo.first, AES128::encryptBlock((ctr + i).getBlock(), key, keySchedule));
        writeBlock(output, blockInfo.first);
        if (finish) {
            break;
        }
    }
}
void GthCryptor::decryptFile(const std::string &inputPath, const std::string &outputPath, std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule) {
    AES128::test();

    std::ifstream input;
    input.open(inputPath);
    if (!input.is_open()) {
        throw NoInputFile();
    }
    uint64_t inputSize = getFileSize(inputPath);

    std::ofstream output;
    output.open(outputPath);
    if (!output.is_open()) {
        throw NoOutputFile();
    }

    UInt128 ctr;
    ctr.setValue(readBlock(input).first);

    if (readBlock(input).first != getKCVBlock(key, keySchedule)) {
        throw InvalidKey();
    }

    int32_t extraBytes = 0;
    for (uint64_t i = 1; true; i = i + 1) {
        std::array<byte, 16> block = readBlock(input).first;
        block = AES128::addRoundKey(block, AES128::encryptBlock((ctr + i).getBlock(), key, keySchedule));
        if (i + 2 == inputSize / 16) {
            while (block[16 - extraBytes - 1] == 0x00) {
                extraBytes = extraBytes + 1;
            }
            extraBytes = extraBytes + 1;
        }
        writeBlock(output, block, extraBytes);
        if (i + 2 == inputSize / 16) {
            break;
        }
    }
}
std::pair<std::array<byte, 16>, int32_t> GthCryptor::readBlock(std::ifstream &input) {
    std::array<byte, 16> block{};
    input.read(reinterpret_cast<char*>(block.data()), 16);
    return std::make_pair(block, input.gcount());
}
void GthCryptor::writeBlock(std::ofstream &output, std::array<byte, 16> block, int32_t extraBytes) {
    output.write(reinterpret_cast<char*>(block.data()), 16 - extraBytes);
}
std::array<byte, 16> GthCryptor::getKCVBlock(std::array<byte, 16> key, std::array<std::array<byte, 16>, 10> keySchedule) {
    std::array<byte, 16> block{};
    for (int32_t i = 0; i < 16; i = i + 1) {
        block[i] = 0x01;
    }
    block = AES128::encryptBlock(block, key, keySchedule);
    for (int32_t i = 6; i < 16; i = i + 1) {
        block[i] = 0x00;
    }
    return block;
}
uint64_t GthCryptor::getFileSize(const std::string &path) {
    std::ifstream file(path, std::ifstream::ate | std::ifstream::binary);
    uint64_t result = file.tellg();
    file.close();
    return result;
}