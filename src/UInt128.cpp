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


#include "UInt128.hpp"


UInt128::UInt128() = default;
UInt128 operator+(UInt128 a, uint64_t b) {
    uint64_t carry = 0;
    for (int32_t i = 15; i >= 0; i = i - 1) {
        uint64_t sum = a.data[i] + b * (i == 15) + carry;
        a.data[i] = sum % 256;
        carry = sum / 256;
    }
    if (carry != 0) {
        throw UInt128::Overflow();
    }
    return a;
}
void UInt128::setValue(std::array<byte, 16> block) {
    this->data = block;
}
void UInt128::setSmallSecureRandomValue() {
    std::random_device rd;
    std::mt19937 mersenne(rd());

    for (int32_t i = 1; i < 16; i = i + 1) {
        this->data[i] = mersenne() % 256;
    }
}
std::array<byte, 16> UInt128::getBlock() const {
    return this->data;
}