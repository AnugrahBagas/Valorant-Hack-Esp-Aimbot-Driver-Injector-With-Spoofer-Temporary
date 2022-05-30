#pragma once
#include <string.h>
#include <string>

class authgg
{
public:
	static void GenerateSeed();
	static void Initialize();
	static int Register(std::string username, std::string password, std::string email, std::string key);
	static void Login(const std::string username, const std::string password);
};