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


#include <sstream>
#include <chrono>
#include "../src/GthCryptor.hpp"


int main() {
    std::cout << "GthCryptor\n"
                 "Copyright (C) 2023 gth-other\n"
                 "\n"
                 "GthCryptor is free software: you can redistribute it and/or modify\n"
                 "it under the terms of the GNU General Public License as published by\n"
                 "the Free Software Foundation, either version 3 of the License, or\n"
                 "(at your option) any later version.\n"
                 "\n"
                 "GthCryptor is distributed in the hope that it will be useful,\n"
                 "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
                 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
                 "GNU General Public License for more details.\n"
                 "\n"
                 "You should have received a copy of the GNU General Public License\n"
                 "along with GthCryptor.  If not, see <http://www.gnu.org/licenses/>.\n\n";

    std::string inputPath, outputPath, action;
    std::string password;
    std::array<byte, 16> key{};
    std::array<std::array<byte, 16>, 10> keySchedule{};

    std::cout << "1. Выполнить шифрование файла." << std::endl;
    std::cout << "2. Выполнить дешифрования файла." << std::endl;
    std::cout << "3. Выход." << std::endl;
    std::cout << "Выберите действие: ";
    std::getline(std::cin, action);
    if (action == "1") {
        std::cout << "Введите путь к файлу, который Вы хотите зашифровать: ";
        std::getline(std::cin, inputPath);
        std::cout << "Введите путь, по которому необходимо сохранить зашифрованную копию: ";
        std::getline(std::cin, outputPath);
        std::cout << "Введите пароль: ";
        std::getline(std::cin, password);
        key = GthCryptor::generateKeyFromPassword(password, 1000000);
        std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
        keySchedule = AES128::keyExpansion(key);
        try {
            GthCryptor::encryptFile(inputPath, outputPath, key, keySchedule);
            std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
            std::cout << "Файл был зашифрован. Сохраните пароль: он необходим для дешифрования." << std::endl;
            std::cout << "Затрачено времени (без учета времени, потраченного на создание ключа из пароля): " << std::chrono::duration_cast<std::chrono::duration<long double>>(t2 - t1).count() << " секунд." << std::endl;
        }
        catch (GthCryptor::NoInputFile &a) {
            std::cout << "Не удалось открыть файл на чтение." << std::endl;
        }
        catch (GthCryptor::NoOutputFile &a) {
            std::cout << "Не удалось открыть файл на запись." << std::endl;
        }
        catch (AES128::AESDoesNotWork &a) {
            std::cout << "Ошибка в реализации AES." << std::endl;
        }
    }
    else if (action == "2") {
        std::cout << "Введите путь к файлу, который Вы хотите дешифровать: ";
        std::getline(std::cin, inputPath);
        std::cout << "Введите путь, по которому необходимо сохранить дешифрованную копию: ";
        std::getline(std::cin, outputPath);
        std::cout << "Введите пароль: ";
        std::getline(std::cin, password);
        key = GthCryptor::generateKeyFromPassword(password, 1000000);
        keySchedule = AES128::keyExpansion(key);
        try {
            GthCryptor::decryptFile(inputPath, outputPath, key, keySchedule);
            std::cout << "Файл был дешифрован." << std::endl;
        }
        catch (GthCryptor::NoInputFile &a) {
            std::cout << "Не удалось открыть файл на чтение." << std::endl;
        }
        catch (GthCryptor::NoOutputFile &a) {
            std::cout << "Не удалось открыть файл на запись." << std::endl;
        }
        catch (GthCryptor::InvalidKey &a) {
            std::cout << "Указан неверный пароль." << std::endl;
        }
        catch (AES128::AESDoesNotWork &a) {
            std::cout << "Ошибка в реализации AES." << std::endl;
        }
    }

    return 0;
}