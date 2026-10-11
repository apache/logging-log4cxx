#include <string>
#include <vector>
#include <iostream>

int main(int argc, char** argv){
	std::vector<std::string> test
	{ std::string("Hello")
	, std::string(" ")
	, std::string("world!.")
	, std::string("\n")
	, std::string("A long string that ensures dynamic memeory is needed")
	};
	for (auto item : test)
		std::cout << item;
	std::cout << '\n';
	return 0;
}

