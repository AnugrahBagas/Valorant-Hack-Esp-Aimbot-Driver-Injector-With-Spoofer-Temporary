#include <windows.h>

#include "..\lazy_importer.hpp"
#include "print.h"
#include <locale.h>

void print::set_color(const int forg_col)
{
	const auto h_std_out = LI_FN(GetStdHandle)(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (GetConsoleScreenBufferInfo(h_std_out, &csbi))
	{
		const WORD w_color = (csbi.wAttributes & 0xF0) + (forg_col & 0x0F);
		LI_FN(SetConsoleTextAttribute)(h_std_out, w_color);
	}
}

void print::set_text(const char* text, const int color)
{
	set_color(color);
	LI_FN(printf)(static_cast<const char*>(text));
	RtlSecureZeroMemory(&text, sizeof(text));
	set_color(White);
}

void print::set_error(const char* text)
{
	set_color(Red);
	LI_FN(printf)(static_cast<const char*>(text));
	RtlSecureZeroMemory(&text, sizeof(text));
	set_color(White);
}

void print::set_warning(const char* text)
{
	set_color(Yellow);
	LI_FN(printf)(static_cast<const char*>(text));
	RtlSecureZeroMemory(&text, sizeof(text));
	set_color(White);
}

void print::set_ok(const char* text)
{
	set_color(Green);
	LI_FN(printf)(static_cast<const char*>(text));
	RtlSecureZeroMemory(&text, sizeof(text));
	set_color(White);
}