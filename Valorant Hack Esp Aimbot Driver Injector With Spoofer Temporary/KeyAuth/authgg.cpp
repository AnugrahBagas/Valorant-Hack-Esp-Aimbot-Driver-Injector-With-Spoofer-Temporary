
#include "authgg.h"
#include "lw_http.hpp"
#include "md5wrapper.h"
#include "print.h"
#include "hwid.h"
#include "xor.h"
#include "crypto.h"
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#include <CkCrypt2.h>
#include <CkBinData.h>
#include <CkJsonArray.h>
#include <CkJsonObject.h>
#include <CkHttp.h>
#include <curl.h>
#pragma comment(lib, "Wldap32")//libcurl için
#pragma comment(lib, "Normaliz")//libcurl için

#include <fstream>
#include "..\api\xor.h"
using namespace std;
extern string Aes256DecryptString(string str, string pw);
using namespace std;
c_crypto crypto;
string server(string toEncrypt) {
	char key[3] = { 'T', 'C', 'P' }; // TCP encrypted data, jk.. unless...
	string output = toEncrypt;

	for (int i = 0; i < toEncrypt.size(); i++)
		output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];

	return output;
}
bool replace(std::string& str, const std::string& from, const std::string& to)
{
	size_t start_pos = str.find(from);
	if (start_pos == std::string::npos)
		return false;
	str.replace(start_pos, from.length(), to);
	return true;
}
void authgg::GenerateSeed()
{
	try
	{
		c_lw_http	lw_http;
		c_lw_httpd	lw_http_d;
		auto md5 = new md5wrapper();
		//https://api.auth.gg/v6/encryption.php
		string enc_php = Aes256DecryptString(xorstr_("l17lMOm4qqZwByaXe/reeqYA3knZafPooaqpiZNRuvIDNtljMQYkoKyUAb6sckT8"), xorstr_("--......"));
		std::string s_reply;
		lw_http_d.add_field(xorstr_("a"), xorstr_("securexseed"));
		auto b_lw_http = lw_http.post(enc_php, s_reply.c_str(), lw_http_d);
		//lw_http_d.clear();

		if (b_lw_http)
		{
			std::string s = server(s_reply);
			crypto.entity = server(s_reply);
			std::string delimiter = xorstr_(":");
			std::vector<std::string> outputArr;
			size_t pos = 0;
			std::string token;
			while ((pos = s.find(delimiter)) != std::string::npos) {
				token = s.substr(0, pos);
				s.erase(0, pos + delimiter.length());
				outputArr.push_back(token);
			}
			outputArr.push_back(s);
			crypto.key = outputArr[0].c_str();
			crypto.iv = outputArr[1].c_str();
			crypto.key_enc = crypto.random_string(256);
		}
	}
	catch (int e)
	{
		cout << xorstr_("An exception occurred. Exception Nr. ") << e << '\n'; getchar(); exit(-1);
	}
}

extern std::string currentDateTime();
void authgg::Initialize()
{
	try
	{
		c_lw_http	lw_http;
		c_lw_httpd	lw_http_d;
		auto md5 = new md5wrapper();

		std::string s_reply;
		lw_http_d.add_field(xorstr_("a"), xorstr_("start"));
		lw_http_d.add_field(xorstr_("b"), crypto.encrypt(crypto.aid, crypto.key, crypto.iv).c_str());
		lw_http_d.add_field(xorstr_("c"), crypto.encrypt(crypto.secret, crypto.key, crypto.iv).c_str());
		lw_http_d.add_field(xorstr_("d"), crypto.encrypt(crypto.apikey, crypto.key, crypto.iv).c_str());
		lw_http_d.add_field(xorstr_("e"), crypto.entity.c_str());
		lw_http_d.add_field(xorstr_("seed"), crypto.key_enc.c_str());

		//https://api.auth.gg/v6/api.php
		string api_php = Aes256DecryptString(xorstr_("rrZxXRzOnQQweethY1+cSBdHxKW71VfSaU78f8KjNDU="), xorstr_(".-.."));
		bool b_lw_http = lw_http.post(api_php, s_reply.c_str(), lw_http_d);
		//lw_http_d.clear();
		//api_php.clear();
		if (b_lw_http)
		{
			if (s_reply.find(xorstr_("|")) != string::npos)
			{

			}
			else
			{
				authgg::GenerateSeed();
				authgg::Initialize();
				return;
			}
			std::string s(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
			/*if (s == ("NOT_PREMIUM"))
			{
			}*/
			std::string delimiter = xorstr_("|");
			std::vector<std::string> outputArr;
			size_t pos = 0;
			std::string token;
			while ((pos = s.find(delimiter)) != std::string::npos) {
				token = s.substr(0, pos);
				s.erase(0, pos + delimiter.length());
				outputArr.push_back(token);
			}
			outputArr.push_back(s);
			std::string status_status = outputArr[0].c_str();
			std::string developermode_status = outputArr[1].c_str();
			std::string hash = outputArr[2].c_str();
			std::string version = outputArr[3].c_str();
			std::string downloadlink = outputArr[4].c_str();
			crypto.freemode_status = outputArr[5].c_str();
			crypto.login_status = outputArr[6].c_str();
			crypto.appname = outputArr[7].c_str();
			crypto.register_status = outputArr[8].c_str();

			if (version != crypto.version)
			{
				system(xorstr_("cls"));
				print::set_text(string(currentDateTime() + xorstr_("New version available! Downloading, please wait..\n")).c_str(), LightGray);

				CkHttp http;
				auto ver_name = string(xorstr_("ValPrivate") + version + xorstr_(".rar"));
				bool success = http.Download(downloadlink.c_str(), ver_name.c_str());
				if (success != true) {
					std::cout << http.lastErrorText() << xorstr_("\r\n");
					return;
				}
				print::set_text(string(currentDateTime() + xorstr_("New version downloaded. Please extract from rar -> [") + ver_name + xorstr_("]")).c_str(), Green);
				//ShellExecute(0, xorstr_("open"), downloadlink.c_str(), 0, 0, SW_SHOW);
				Sleep(6000);
				exit(43);
			}
			if (status_status != xorstr_("Enabled"))
			{
				print::set_error(xorstr_("Loader has been disabled!"));
				Sleep(3000);
				exit(43);
			}
			//lw_http.close_session();
		}
	}
	catch (int e)
	{
		cout << xorstr_("An exception occurred. Exception Nr. ") << e << '\n';
	}
}

int authgg::Register(std::string username, std::string password, std::string email, std::string key)
{
	return 0;
};

void authgg::Login(const std::string username, const std::string password)
{
//	c_lw_http	lw_http;
//	c_lw_httpd	lw_http_d;
//	auto md5 = new md5wrapper();
//	if (!lw_http.open_session())
//	{
//		return;
//	}
//sa:
//	std::string s_reply;
//	lw_http_d.add_field(("a"), ("login"));
//	lw_http_d.add_field(("b"), crypto.encrypt(crypto.aid, crypto.key, crypto.iv).c_str());
//	lw_http_d.add_field(("c"), crypto.encrypt(crypto.secret, crypto.key, crypto.iv).c_str());
//	lw_http_d.add_field(("d"), crypto.encrypt(crypto.apikey, crypto.key, crypto.iv).c_str());
//	lw_http_d.add_field(("g"), crypto.encrypt(username, crypto.key, crypto.iv).c_str());
//	lw_http_d.add_field(("h"), crypto.encrypt(password, crypto.key, crypto.iv).c_str());
//	lw_http_d.add_field(("k"), md5->getHashFromString(hwid::get_hardware_id("1")).c_str());
//	lw_http_d.add_field(("e"), crypto.entity.c_str());
//	lw_http_d.add_field(("seed"), crypto.key_enc.c_str());
//
//	//https://api.auth.gg/v6/api.php
//	string api_php = Aes256DecryptString(("rrZxXRzOnQQweethY1+cSBdHxKW71VfSaU78f8KjNDU="), (".-.."));
//	auto b_lw_http = lw_http.post(api_php, s_reply, lw_http_d);
//	lw_http_d.clear();
//	api_php = "xxxxxxxxxxxxxxxxxxxxxxxx";
//	api_php = ("xxxxxxxxxxxxxxxxxxxxxxxx");
//	api_php.clear();
//	RtlSecureZeroMemory(&api_php, api_php.size());
//	if (s_reply.length() > 50)
//	{
//	
//		if (b_lw_http)
//		{
//			if (crypto.login_status == "Disabled")
//			{
//				std::string s(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
//				Sleep(2000);
//				exit(43);
//			}
//			std::string s(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
//			if (s == "hwid_updated")
//			{
//				print::set_text("SUCCESS : Your HWID has been updated!", Green);
//				Sleep(2000);
//				exit(43);
//			}
//			if (s == "time_expired")
//			{
//				print::set_text("ERROR : Subscription has expired!", Red);
//				Sleep(2000);
//				exit(43);
//			}
//			if (s == "invalid_hwid")
//			{
//				print::set_text("ERROR : Your HWID does not match!", Red);
//				Sleep(2000);
//				exit(43);
//			}
//			if (s == "invalid_details")
//			{
//				print::set_text("ERROR : Your credentials are invalid!", Red);
//				Sleep(2000);
//				exit(43);
//			}
//			std::string delimiter = "|";
//			std::vector<std::string> outputArr;
//			size_t pos = 0;
//			std::string token;
//			while ((pos = s.find(delimiter)) != std::string::npos) {
//				token = s.substr(0, pos);
//				s.erase(0, pos + delimiter.length());
//				outputArr.push_back(token);
//			}
//			outputArr.push_back(s);
//			std::string login = outputArr[0].c_str();
//			std::string hwid = outputArr[1].c_str();
//			std::string email = outputArr[2].c_str();
//			std::string rank = outputArr[3].c_str();
//			std::string ip = outputArr[4].c_str();
//			std::string expiry = outputArr[5].c_str();
//			std::string uservariable = outputArr[6].c_str();
//			if (login == "success" + crypto.apikey + crypto.aid + ip)
//			{
//				print::set_text("SUCCESS : You have successfully logged in! \n", Green);
//				print::set_text("-User Info- \n", Blue);
//				print::set_text("HWID: ", LightBlue);
//				print::set_text(hwid.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				print::set_text("Email: ", LightBlue);
//				print::set_text(email.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				print::set_text("Rank: ", LightBlue);
//				print::set_text(rank.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				print::set_text("IP: ", LightBlue);
//				print::set_text(ip.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				print::set_text("Expiry: ", LightBlue);
//				print::set_text(expiry.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				print::set_text("User Variable: ", LightBlue);
//				print::set_text(uservariable.c_str(), LightBlue);
//				print::set_text("\n", LightBlue);
//				Sleep(2000);
//				exit(43);
//			}
//			/*if (!b_lw_http)
//			{
//				return;
//			}*/
//		}
//		lw_http.close_session();
//	}
//	else
//		goto sa;
}