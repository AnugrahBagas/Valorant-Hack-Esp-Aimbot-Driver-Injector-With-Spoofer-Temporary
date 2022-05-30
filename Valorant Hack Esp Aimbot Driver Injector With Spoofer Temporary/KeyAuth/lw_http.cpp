#define CURL_STATICLIB
#include "lw_http.hpp"
#include <curl.h>
#include "..\api\xor.h"
static const std::string g_s_base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

bool lw_http_tools::is_base64(const BYTE u_ch)
{
	return (isalnum(u_ch) || (u_ch == '+') || (u_ch == '/'));
}

std::string lw_http_tools::encode_base64(const char* psz_input)
{
	size_t uInputSize = strlen(psz_input);
	int I = 0;
	int J = 0;

	BYTE ucArray3[3];
	BYTE ucArray4[4];

	std::string sResult;

	while (uInputSize--)
	{
		ucArray3[I++] = *(psz_input++);

		if (I == 3)
		{
			ucArray4[0] = (ucArray3[0] & 0xfc) >> 2;
			ucArray4[1] = ((ucArray3[0] & 0x03) << 4) + ((ucArray3[1] & 0xf0) >> 4);
			ucArray4[2] = ((ucArray3[1] & 0x0f) << 2) + ((ucArray3[2] & 0xc0) >> 6);
			ucArray4[3] = ucArray3[2] & 0x3f;

			for (I = 0; (I < 4); I++)
				sResult += g_s_base64_chars[ucArray4[I]];
			I = 0;
		}
	}

	if (I)
	{
		for (J = I; J < 3; J++)
			ucArray3[J] = '\0';

		ucArray4[0] = (ucArray3[0] & 0xfc) >> 2;
		ucArray4[1] = ((ucArray3[0] & 0x03) << 4) + ((ucArray3[1] & 0xf0) >> 4);
		ucArray4[2] = ((ucArray3[1] & 0x0f) << 2) + ((ucArray3[2] & 0xc0) >> 6);
		ucArray4[3] = ucArray3[2] & 0x3f;

		for (J = 0; (J < I + 1); J++)
			sResult += g_s_base64_chars[ucArray4[J]];

		while ((I++ < 3))
			sResult += '=';
	}

	return sResult;
}

std::string lw_http_tools::decode_base64(std::string const& s_input)
{
	size_t uInputSize = s_input.size();
	int i = 0;
	int j = 0;
	int n_in = 0;

	BYTE uc_array3[3];
	BYTE uc_array4[4];

	std::string s_result;

	while (uInputSize-- && (s_input[n_in] != '=') && is_base64(s_input[n_in]))
	{
		uc_array4[i++] = s_input[n_in]; n_in++;

		if (i == 4)
		{
			for (i = 0; i < 4; i++)
				uc_array4[i] = g_s_base64_chars.find(uc_array4[i]);

			uc_array3[0] = (uc_array4[0] << 2) + ((uc_array4[1] & 0x30) >> 4);
			uc_array3[1] = ((uc_array4[1] & 0xf) << 4) + ((uc_array4[2] & 0x3c) >> 2);
			uc_array3[2] = ((uc_array4[2] & 0x3) << 6) + uc_array4[3];

			for (i = 0; i < 3; i++)
				s_result += uc_array3[i];

			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 4; j++)
			uc_array4[j] = 0;

		for (j = 0; j < 4; j++)
			uc_array4[j] = g_s_base64_chars.find(uc_array4[j]);

		uc_array3[0] = (uc_array4[0] << 2) + ((uc_array4[1] & 0x30) >> 4);
		uc_array3[1] = ((uc_array4[1] & 0xf) << 4) + ((uc_array4[2] & 0x3c) >> 2);
		uc_array3[2] = ((uc_array4[2] & 0x3) << 6) + uc_array4[3];

		for (j = 0; (j < i - 1); j++)
			s_result += uc_array3[j];
	}

	return s_result;
}

std::string lw_http_tools::url_encode(std::string s_input)
{
	std::string s_result;
	s_result.reserve(s_input.length());

	for (size_t I = 0; I < s_input.length(); ++I)
	{
		char ch = s_input[I];

		if ((ch < 33) || (ch > 126) || strchr("!\"#%&'*,:;<=>?[]^`{|} ", ch))
		{
			char sz_buffer[4];
			sprintf_s(sz_buffer, xorstr_("%%%02x"), ch & 0xFF);
			s_result += sz_buffer;
		}
		else
			s_result += ch;
	}
	//RtlSecureZeroMemory(&s_input, s_input.size());
	return s_result;
}

std::string lw_http_tools::url_decode(std::string s_input)
{
	std::string s_result;
	s_result.reserve(s_input.length());

	char szBuffer[4];
	szBuffer[2] = '\0';

	const char* psz_input = s_input.c_str();
	RtlSecureZeroMemory(&s_input, sizeof(s_input));
	while (*psz_input)
	{
		if (*psz_input == '%' && psz_input[1] && psz_input[2])
		{
			szBuffer[0] = psz_input[1];
			szBuffer[1] = psz_input[2];
			s_result += (char)(strtoul(szBuffer, NULL, 16));
			psz_input += 3;
		}
		else
		{
			s_result += *psz_input;
			++psz_input;
		}
	}
	//RtlSecureZeroMemory(&psz_input, sizeof(psz_input));
	return s_result;
}

///////////////////////////////////////////////////////////////////////////////

void c_lw_httpd::fmt_out(const PCHAR pszFieldName, const PCHAR pszFmt, ...)
{
    char sz_value[2048];
	ZeroMemory(sz_value, sizeof(sz_value));

	va_list VAList;
	va_start(VAList, pszFmt);
	_vsnprintf_s(sz_value, sizeof(sz_value), pszFmt, VAList);
	va_end(VAList);

	std::string sValueEncoded = lw_http_tools::url_encode(sz_value);

	char szOut[2048];
	RtlSecureZeroMemory(szOut, sizeof(szOut));
	//sprintf_s( szOut, "&%s=%s", pszFieldName, szValue );
	sprintf_s(szOut, xorstr_("&%s=%s"), pszFieldName, sValueEncoded.c_str());
	//RtlSecureZeroMemory(pszFieldName, sizeof(pszFieldName));
	//RtlSecureZeroMemory(pszFmt, sizeof(pszFmt));

	m_s_data_ += szOut;
}

void c_lw_httpd::add_field(const PCHAR pszName, const char* pszValue)
{
	fmt_out(pszName, (PCHAR)("%s"), pszValue);
	RtlSecureZeroMemory(&pszValue, sizeof(pszValue));
}

void c_lw_httpd::add_field(const PCHAR pszName, float fValue)
{
	fmt_out(pszName, (PCHAR)("%f"), fValue);
	RtlSecureZeroMemory(pszName, sizeof(pszName));
	RtlSecureZeroMemory(&fValue, sizeof(fValue));
}

void c_lw_httpd::add_field(const PCHAR pszName, int iValue)
{
	fmt_out(pszName, (PCHAR)("%i"), iValue);
	RtlSecureZeroMemory(pszName, sizeof(pszName));
	RtlSecureZeroMemory(&iValue, sizeof(iValue));
}

const char* c_lw_httpd::get_data(void) const
{
	return &(m_s_data_.data()[1]);
}

DWORD c_lw_httpd::get_size(void) const
{
	return m_s_data_.length() - 1;
}

void c_lw_httpd::clear(void)
{
	m_s_data_.clear();
}

///////////////////////////////////////////////////////////////////////////////

c_lw_http::c_lw_http(void) : m_dw_last_reply_size_(0)
{
	m_h_session_ = nullptr;
	m_psz_referer_ = L"";
	m_psz_user_agent_ = LWHTTP_USER_AGENT;
}

c_lw_http::~c_lw_http(void)
{
}

bool c_lw_http::open_session(void)
{
	if (m_h_session_) return false;

	m_h_session_ = ::WinHttpOpen(m_psz_user_agent_, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	return (m_h_session_ ? true : false);
}

void c_lw_http::close_session(void) const
{
	if (m_h_session_)
		::WinHttpCloseHandle(m_h_session_);
}

bool c_lw_http::set_referer(PWCHAR pszReferer)
{
	if (!pszReferer) return false;

	m_psz_referer_ = pszReferer;

	return true;
}

PWCHAR c_lw_http::get_referer(void) const
{
	return m_psz_referer_;
}

bool c_lw_http::set_user_agent(PWCHAR pszUserAgent)
{
	if (!pszUserAgent || m_h_session_) return false;

	m_psz_user_agent_ = pszUserAgent;

	return true;
}

PWCHAR c_lw_http::get_user_agent(void) const
{
	return m_psz_user_agent_;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

bool c_lw_http::get(std::string sURL, std::string& s_reply)
{
	CURL* curl;
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, sURL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s_reply);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			sURL.clear();
			RtlSecureZeroMemory(&sURL, sizeof(sURL));
			fprintf(stderr, xorstr_("curl_easy_perform() failed: %s\n"), curl_easy_strerror(res));
			return false;
		}
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	curl = NULL;
	sURL.clear();
	RtlSecureZeroMemory(&sURL, sizeof(sURL));
	return true;
}

bool c_lw_http::post(std::string sURL, const char* sReply, c_lw_httpd& PostData)
{
	curl_global_init(CURL_GLOBAL_ALL);
	CURLcode res;
	CURL* curl = curl_easy_init();
	if (curl) 
	{
		curl_easy_setopt(curl, CURLOPT_URL, sURL.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, PostData.get_data());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, sReply);
		res = curl_easy_perform(curl);
		if (res != CURLE_OK) 
		{
			sURL.clear();
			RtlSecureZeroMemory(&sURL, sizeof(sURL));
			fprintf(stderr, xorstr_("curl_easy_perform() failed: %s\n"), curl_easy_strerror(res));
			curl_easy_cleanup(curl);
			return false;
		}	
		curl_easy_cleanup(curl);
	}	
	curl_global_cleanup();
	curl = NULL;	
	sURL.clear();
	RtlSecureZeroMemory(&sURL, sizeof(sURL));
	return true;	
}