#include <iostream>
#include <chrome.hpp>

int main()
{
	std::multimap<std::string, std::string> ret;

	get_chrome(ret);

	for (auto &value : ret)
		std::cout << value.first << ": " << value.second << std::endl;
	return 0;
}