#include <cassert>
#include <fstream>
#include <ios>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <ostream>
#include <stdexcept>
#include <vector>

using std::string;
using std::vector;

void encrypt_file(const string &source_filepath, const string &output_filepath, const string &key, unsigned char *iv,
                  size_t iv_len, size_t chunk_size = 128)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("failed to initialize evp_cipher_ctx");
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to initialize AES-256-GCM");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set iv_len");
    }

    if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, (unsigned char *)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set key and iv");
    }

    std::fstream fin(source_filepath, std::ios_base::in);
    std::fstream fout(output_filepath, std::ios_base::out);

    const size_t padding = 1024;
    vector<unsigned char> cipher_text(chunk_size + padding);
    vector<unsigned char> tag(16);
    vector<char> buffer(chunk_size);
    int len;

    while (!fin.eof()) {
        fin.read(buffer.data(), buffer.size());
        std::streamsize n = fin.gcount();
        if (!EVP_EncryptUpdate(ctx, cipher_text.data(), &len, (unsigned char *)buffer.data(), (int)n)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        fout.write((char *)cipher_text.data(), len);
    }

    if (!EVP_EncryptFinal_ex(ctx, cipher_text.data(), (int *)&len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    if (len > 0) {
        fout.write((char *)cipher_text.data(), len);
    }

    // Get tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to get tag");
    }

    fout.write((char *)tag.data(), tag.size());
    EVP_CIPHER_CTX_free(ctx);
    BIO_dump_fp(stdout, tag.data(), 16);

    fout.close();
    fin.close();
}

void decrypt_file(const string &source_filepath, const string &output_filepath, const string &key, unsigned char *iv,
                  size_t iv_len, size_t chunk_size = 128)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("failed to initialize evp_cipher_ctx");
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to initialize AES-256-GCM");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set iv_len");
    }

    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, (unsigned char *)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set key and iv");
    }

    std::fstream fin(source_filepath, std::ios_base::in);
    std::fstream fout(output_filepath, std::ios_base::out);

    // Get tag from the file
    vector<unsigned char> tag(16);
    fin.seekg(0, std::ios_base::end);
    int length = fin.tellg();
    assert(length >= 16 && "content length must be greater than the tag length");
    fin.seekg(length - 16, std::ios_base::beg);
    auto tag_start_location = fin.tellg();
    fin.read((char *)tag.data(), tag.size());

    // read from beginning
    fin.seekg(0, std::ios_base::beg);

    const size_t padding = 1024;
    vector<unsigned char> plaintext(1024 + chunk_size);
    vector<char> buffer(chunk_size + padding);
    int len;

    int pos = 0;

    bool quit = false;

    while (!fin.eof() && !quit) {
        fin.read(buffer.data(), buffer.size());
        std::streamsize n = fin.gcount();
        pos += n;
        if (pos >= length - 16) {
            n -= (pos - length + 16);
            pos = length - 16;
            quit = true;
        }
        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char *)buffer.data(), (int)n)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }
        fout.write((char *)plaintext.data(), len);
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set tag while decrypting");
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data(), (int *)&len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }

    if (len > 0) {
        fout.write((char *)plaintext.data(), len);
    }

    EVP_CIPHER_CTX_free(ctx);

    fout.close();
    fin.close();
}

int main(void)
{
    try {
        encrypt_file("main.cpp", "main.cpp.enc", "01234567890123456789012345678901",
                     (unsigned char *)"0123456789012345", 16);

        decrypt_file("main.cpp.enc", "main.cpp.dec", "01234567890123456789012345678901",
                     (unsigned char *)"0123456789012345", 16);

    } catch (std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
