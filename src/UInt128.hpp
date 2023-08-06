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


#include <iostream>
#include <array>
#include <fstream>
#include <random>
#include "Byte.hpp"


#pragma once


class UInt128 {
public:
    UInt128();

    friend UInt128 operator +(UInt128 a, uint64_t b);

    void setValue(std::array<byte, 16> block);
    void setSmallSecureRandomValue();

    [[nodiscard]] std::array<byte, 16> getBlock() const;

    class Overflow : public std::exception {};
private:
    std::array<byte, 16> data{};
};