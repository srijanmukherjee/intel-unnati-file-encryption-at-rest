#include "file_cipher.hpp"

#include <cassert>
#include <ios>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/types.h>
#include <vector>

const EVP_CIPHER *AES256GCM_FileCipher::m_cipher = EVP_aes_256_gcm();

AES256GCM_FileCipher::AES256GCM_FileCipher(const std::string &key, const std::string &iv) : m_key(key), m_iv(iv)
{
    // size(key) = 256 bits = 32 bytes
    // size(iv)  = 128 bits = 16 bytes
    assert(key.size() == 32 && "key must be 256 bits long");
    assert(iv.size() == 16 && "iv must be 128 bits long");

    if (m_cipher == nullptr) {
        throw std::runtime_error("AES-256-GCM not available");
    }

    m_ctx = EVP_CIPHER_CTX_new();
    if (m_ctx == nullptr) {
        throw std::runtime_error("failed to create EVP_CIPHER context");
    }
}

AES256GCM_FileCipher::~AES256GCM_FileCipher()
{
    if (m_ctx != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx);
    }
}

void AES256GCM_FileCipher::encrypt(std::istream &input_stream, std::ostream &output_stream)
{
    if (!EVP_CIPHER_CTX_reset(m_ctx)) {
        throw std::runtime_error("failed to reset EVP_CIPHER context");
    }

    if (m_ctx == nullptr) {
        throw std::runtime_error("failed to initialize EVP_CIPHER_CTX");
    }

    if (!EVP_EncryptInit_ex(m_ctx, m_cipher, nullptr, nullptr, nullptr)) {
        throw std::runtime_error("failed to initialize AES-256-GCM encryption");
    }

    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_IVLEN, m_iv.size(), NULL)) {
        throw std::runtime_error("failed to set IV length");
    }

    if (!EVP_EncryptInit_ex(m_ctx, nullptr, nullptr, (unsigned char *)m_key.c_str(), (unsigned char *)m_iv.c_str())) {
        throw std::runtime_error("failed to set key and iv");
    }

    std::vector<unsigned char> cipher_buf(PLAINTEXT_CHUNK_SIZE + EVP_CIPHER_get_block_size(m_cipher) - 1);
    std::vector<char> buf(PLAINTEXT_CHUNK_SIZE);
    std::vector<unsigned char> tag(16);
    int outl;

    // encrypt input stream
    while (!input_stream.eof()) {
        input_stream.read(buf.data(), buf.size());
        auto inl = input_stream.gcount();

        if (!EVP_EncryptUpdate(m_ctx, cipher_buf.data(), &outl, (unsigned char *)buf.data(), inl)) {
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }

        output_stream.write((char *)cipher_buf.data(), outl);
    }

    if (!EVP_EncryptFinal_ex(m_ctx, cipher_buf.data(), &outl)) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    if (outl > 0) {
        output_stream.write((char *)cipher_buf.data(), outl);
    }

    // compute tag
    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        throw std::runtime_error("failed to get tag");
    }

    output_stream.write((char *)tag.data(), tag.size());
}

void AES256GCM_FileCipher::decrypt(std::istream &input_stream, std::ostream &output_stream)
{
    if (!EVP_CIPHER_CTX_reset(m_ctx)) {
        throw std::runtime_error("failed to reset EVP_CIPHER context");
    }

    if (!EVP_DecryptInit_ex(m_ctx, m_cipher, NULL, nullptr, nullptr)) {
        throw std::runtime_error("failed to initialize AES-256-GCM decryption");
    }

    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_IVLEN, m_iv.size(), nullptr)) {
        throw std::runtime_error("failed to set IV length");
    }

    if (!EVP_DecryptInit_ex(m_ctx, nullptr, nullptr, (unsigned char *)m_key.data(), (unsigned char *)m_iv.data())) {
        throw std::runtime_error("failed to set key and iv");
    }

    // extract tag
    const int tag_size = 16;
    std::vector<unsigned char> tag(tag_size);

    input_stream.seekg(0, std::ios_base::end);
    ssize_t length = input_stream.tellg();

    if (length == -1) {
        throw std::runtime_error("failed to compute length of content");
    }

    if (length < (ssize_t)tag.size()) {
        throw std::runtime_error("Content length is less than tag size");
    }

    input_stream.seekg(length - tag.size(), std::ios_base::beg);
    input_stream.read((char *)tag.data(), tag.size());
    input_stream.seekg(0, std::ios_base::beg);

    std::vector<char> buf(PLAINTEXT_CHUNK_SIZE + EVP_CIPHER_get_block_size(m_cipher) - 1);
    std::vector<unsigned char> plaintext_buf(PLAINTEXT_CHUNK_SIZE);
    size_t pos = 0;
    int outl;

    while (!input_stream.eof() && pos <= length - tag.size()) {
        input_stream.read(buf.data(), buf.size());
        auto inl = input_stream.gcount();

        pos += inl;

        // do not read into the tag
        if (pos > length - tag.size()) {
            inl -= pos - length + tag.size();
        }

        if (!EVP_DecryptUpdate(m_ctx, plaintext_buf.data(), &outl, (unsigned char *)buf.data(), inl)) {
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }

        output_stream.write((char *)plaintext_buf.data(), outl);
    }

    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        throw std::runtime_error("failed to set tag");
    }

    if (!EVP_DecryptFinal_ex(m_ctx, plaintext_buf.data(), &outl)) {
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }

    if (outl > 0) {
        output_stream.write((char *)plaintext_buf.data(), outl);
    }
}