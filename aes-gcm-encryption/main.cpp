#include "file_cipher.hpp"

#include <fstream>

int main(void)
{
    FileCipher *file_cipher = new AES256GCM_FileCipher("01234567890123456789012345678901", "0123456789012345");

    std::ifstream fin("./main.cpp");
    std::ofstream fout("./main.cpp.enc");

    file_cipher->encrypt(fin, fout);

    return 0;
}