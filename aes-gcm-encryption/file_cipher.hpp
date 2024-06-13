#pragma once

#include <istream>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <ostream>

#define PLAINTEXT_CHUNK_SIZE 256

class FileCipher
{
public:
    virtual void encrypt(std::istream &input_stream, std::ostream &output_stream) = 0;
    virtual void decrypt(std::istream &input_stream, std::ostream &output_stream) = 0;
};

class AES256GCM_FileCipher : public FileCipher
{
public:
    AES256GCM_FileCipher(const std::string &key, const std::string &iv);
    ~AES256GCM_FileCipher();

    void encrypt(std::istream &input_stream, std::ostream &output_stream) override;
    void decrypt(std::istream &input_stream, std::ostream &output_stream) override;

private:
    static const EVP_CIPHER *m_cipher;
    EVP_CIPHER_CTX *m_ctx = nullptr;
    std::string m_key;
    std::string m_iv;
};