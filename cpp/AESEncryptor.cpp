#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib,"libssl.lib")

std::string base64_encode(const unsigned char* input, int length) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return std::string(bufferPtr->data, bufferPtr->length);
}

std::string pkcs5_pad(const std::string& text) {
    int padding = AES_BLOCK_SIZE - (text.size() % AES_BLOCK_SIZE);
    std::string paddedText = text;
    paddedText.append(padding, static_cast<char>(padding));
    return paddedText;
}

std::string aes_encrypt(const std::string& text, const std::string& key) {
    if (text.empty() || key.empty()) {
        return "";
    }

    std::string paddedText = pkcs5_pad(text);

    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 256, &aesKey) < 0) {
        std::cerr << "AES_set_encrypt_key failed" << std::endl;
        return "";
    }

    std::string output;
    int textSize = paddedText.size();
    unsigned char* encryptedText = new unsigned char[textSize];
    memset(encryptedText, 0, textSize);

    AES_ecb_encrypt(reinterpret_cast<const unsigned char*>(paddedText.c_str()), encryptedText, &aesKey, AES_ENCRYPT);

    output = base64_encode(encryptedText, textSize);
    delete[] encryptedText;

    return output;
}

std::string base64_decode(const std::string& input) {
    BIO* bio, * b64;
    std::string output;
    int decodedSize = 0;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);

    // Ignore newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Determine output size and allocate memory
    output.resize(input.length());  // Base64 encoding increases size by at most 4/3
    decodedSize = BIO_read(bio, &output[0], input.length());

    BIO_free_all(bio);

    // Resize output to actual length
    output.resize(decodedSize);

    return output;
}

std::string aes_decrypt(const std::string& encryptedText, const std::string& key) {
    if (encryptedText.empty() || key.empty()) {
        return "";
    }

    std::string paddedText = base64_decode(encryptedText);

    AES_KEY aesKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 256, &aesKey) < 0) {
        std::cerr << "AES_set_decrypt_key failed" << std::endl;
        return "";
    }

    std::string output;
    int textSize = paddedText.size();
    unsigned char* decryptedText = new unsigned char[textSize];
    memset(decryptedText, 0, textSize);

    AES_ecb_encrypt(reinterpret_cast<const unsigned char*>(paddedText.c_str()), decryptedText, &aesKey, AES_DECRYPT);

    // Remove padding
    int padding = decryptedText[textSize - 1];
    output.assign(reinterpret_cast<char*>(decryptedText), textSize - padding);

    delete[] decryptedText;

    return output;
}

//int main() {
    //std::string text = "Hello, World!";
    //std::string key = "01234567890123456789012345678901"; // 32-byte key

    //std::string encryptedText = aes_encrypt(text, key);
    //std::cout << "Encrypted text: " << encryptedText << std::endl;
    //std::string decryptedText = aes_decrypt(encryptedText, key);
    //std::cout << "Decrypted text: " << decryptedText << std::endl;
//}
