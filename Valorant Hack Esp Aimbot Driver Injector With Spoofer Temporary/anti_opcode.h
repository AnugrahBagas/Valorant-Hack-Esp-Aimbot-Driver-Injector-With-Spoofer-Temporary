#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <TlHelp32.h>
#include "api/xor.h"
#include <Psapi.h>

#include <VMProtectSDK.h>
namespace anti
{
    struct s_opcode
    {
        s_opcode(void* a1, int a2, bool a3, std::string a4)
        {
            region = a1;
            size = a2;
            critical = a3;
            name = a4;
            prep();
        }
        /*given*/
        std::string name;
        bool critical;
        int size;
        void* region;
        /*scan*/
        std::vector<int> original; /*original sequence of bytes*/
        /*helper*/
        void prep()
        {
            if (size != 0) /*set region*/
            {
                for (auto c = 0; c < size; c++)
                {
                    const auto ptr = (uint8_t*)region + c;
                    const auto opcode = ptr;
                    const auto disasm_opcode = *opcode;
                    original.push_back(disasm_opcode);
                }
            }
            else /*scan until we hit function end*/
            {
                auto last_result = int();
                auto cnt = 0;
                while (last_result != 0xc3)/*0xc3 ret*/
                {
                    const auto ptr = (uint8_t*)region + cnt;
                    const auto opcode = ptr;
                    const auto opc = *opcode;
                    original.push_back(opc);
                    cnt++;
                    last_result = opc;
                }
                size = cnt - 1;
                original.pop_back();
                /*delete 0xc3*/
            }
        }
    };
    class c_opcode
    {
    public:
        auto setup() -> bool;
        auto add(void* region, int region_size, bool critical, std::string name) -> bool;
        auto log(std::string str) -> void;
        static auto get_opcode(std::vector<s_opcode>::value_type& e)->std::vector<int>;
        void work();
    private:
        std::vector<s_opcode> guard_sections;
        std::vector<std::string> logs;
    };
    extern c_opcode* p_opcode;
}

auto anti::c_opcode::setup() -> bool
{
    return true;
}
/**
 * \brief adds memory region to be guarded
 * \param region region that needs to be protected
 * \param region_size if (region==0) (automatic function size) else (custom region size)
 * \param critical when true will force the process to close
 * \param name debug pseudo name
 */

auto anti::c_opcode::add(void* region, int region_size, bool critical, std::string name) -> bool
{
    /*getting the actual function if we in the rttable*/
    auto gb = [&](int add) -> const uint8_t
    {
        const auto ptr = (uint8_t*)region + add;
        const auto opcode = ptr;
        const auto opc = *opcode;
        return opc;
    };

    //VMProtectBeginUltra("opca");

    unsigned long long res = 0;
    auto first_bt = gb(0x0);

    if (first_bt == 0xe9)
    {
        auto last_read = 0;
        auto mempad = 0;
        std::stringstream adr_content;
        while (last_read != 0xe9)
        {
            mempad++;
            last_read = gb(mempad);

            if (last_read != 0xe9) adr_content << std::hex << last_read;
        }
        /*convert*/
        auto final_adr = (DWORD64)region + 0x5;

        std::stringstream reorg;
        reorg << adr_content.str().at(2);
        reorg << adr_content.str().at(3);
        reorg << adr_content.str().at(0);
        reorg << adr_content.str().at(1);

        auto relastoi = std::stoul(reorg.str(), nullptr, 16);
        auto funcadr = final_adr + relastoi;
        res = funcadr;
    }
    else res = (unsigned long long)region;
    this->guard_sections.emplace_back((void*)res, region_size, critical, name);

    //std::cout << stra("([]) guarding function 0x") << std::hex << res << std::endl;

    //VMProtectEnd();

    return true;
}

auto anti::c_opcode::log(const std::string str) -> void
{
    this->logs.push_back(str);
}

auto anti::c_opcode::get_opcode(std::vector<anti::s_opcode>::value_type& e) -> std::vector<int>
{
    auto cur_opcode = std::vector<int>();
    for (auto c = 0; c < e.size; c++)
    {
        const auto ptr = (uint8_t*)e.region + c;
        const auto opcode = ptr;
        const auto disasm_opcode = *opcode;
        cur_opcode.push_back(disasm_opcode);
    }
    return cur_opcode;
}

void anti::c_opcode::work()
{
    VMProtectBeginUltra("opcw");
    if (this->guard_sections.empty()) return;
    for (auto e : this->guard_sections)
    {
        auto cur = get_opcode(e);
        for (auto f = 0; f < e.size; f++)
        {
            const auto cur_ = cur.at(f);
            const auto ori_ = e.original.at(f);
            if (cur_ != ori_)
            {
                const auto ptr = (uint8_t*)e.region + f;
                if (e.critical)
                    ExitProcess(0);
                WriteProcessMemory(GetCurrentProcess(), (void*)ptr, &ori_, 1, nullptr);
            }
        }
    }
    VMProtectEnd();
}

anti::c_opcode* anti::p_opcode;

namespace anti
{
    struct s_handle_info
    {
        unsigned long pid;
        HWND		  hndl;
    };
    struct s_process_info
    {
        s_process_info(WCHAR a1[MAX_PATH], const DWORD a2, TCHAR a3[260], const char a4[MAX_PATH])
        {
            std::wstring ws(a1);
            const std::string str(ws.begin(), ws.end());
            const std::string str2(a3);
            proc_id = a2;
            exe_name = str;
            full_path = str2;
            title = a4;
        }
        std::string exe_name;
        std::string full_path;
        std::string title;
        DWORD proc_id;
    };

    class c_proc
    {
    private:
        PROCESS_INFORMATION open(const int pid);
        HWND				findmain(unsigned long pid);
        std::vector< s_process_info> get();
        void				scan(std::vector<std::basic_string<char>>& blacklist_procname,
            std::vector<std::basic_string<char>>& blacklist_title,
            std::vector<s_process_info>::value_type obj, uint32_t sum) const;
    public:
        bool				ismain(const HWND hndl);
        void				work();
        bool				stealththrd(HANDLE hThread);

    };
    extern c_proc* p_proc;
}

PROCESS_INFORMATION anti::c_proc::open(const int pid)
{
    auto info = PROCESS_INFORMATION();
    if (!pid) { return {}; }
    info.hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, 0, pid);
    if (info.hProcess) return info;
}
bool anti::c_proc::ismain(const HWND hndl)
{
    return GetWindow(hndl, GW_OWNER) == HWND(nullptr) && IsWindowVisible(hndl);
}
BOOL CALLBACK enum_window(HWND hndl, LPARAM param)
{
    auto& data = *(anti::s_handle_info*)param;
    unsigned long pid;
    GetWindowThreadProcessId(hndl, &pid);
    if (data.pid != pid || !anti::p_proc->ismain(hndl)) return 1;
    data.hndl = hndl;
    return 0;
}
HWND anti::c_proc::findmain(unsigned long pid)
{
    anti::s_handle_info info;
    info.pid = pid; info.hndl = nullptr;
    EnumWindows(enum_window, (LPARAM)&info);
    return info.hndl;
}
std::vector<anti::s_process_info> anti::c_proc::get()
{
    auto list = std::vector<s_process_info>();
    const auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    auto pentry32 = PROCESSENTRY32W();
    if (handle == INVALID_HANDLE_VALUE) return {};
    pentry32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(handle, &pentry32))
    {
        TCHAR filename[MAX_PATH];
        auto pehandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pentry32.th32ProcessID);
        GetModuleFileNameEx(pehandle, nullptr, filename, MAX_PATH);
        CloseHandle(pehandle);

        auto wnd = this->findmain(pentry32.th32ProcessID);
        char wnd_title[MAX_PATH];
        if (wnd) GetWindowTextA(wnd, wnd_title, sizeof(wnd_title));

        list.emplace_back(pentry32.szExeFile, pentry32.th32ProcessID, filename, wnd_title);
        while (Process32NextW(handle, &pentry32))
        {
            auto pehandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pentry32.th32ProcessID);
            GetModuleFileNameEx(pehandle, nullptr, filename, MAX_PATH);
            CloseHandle(pehandle);

            wnd = this->findmain(pentry32.th32ProcessID);
            if (wnd) GetWindowTextA(wnd, wnd_title, sizeof(wnd_title));

            list.emplace_back(pentry32.szExeFile, pentry32.th32ProcessID, filename, wnd_title);
        }
    }
    return list;
}
void anti::c_proc::scan(std::vector<std::basic_string<char>>& blacklist_procname,
    std::vector<std::basic_string<char>>& blacklist_title,
    std::vector<s_process_info>::value_type obj,
    uint32_t sum) const
{
    for (auto bobj : blacklist_procname)
    {
        if (strstr(obj.exe_name.c_str(), bobj.c_str()))
            abort();
    }
    for (auto bobj : blacklist_title)
    {
        if (strstr(obj.title.c_str(), bobj.c_str()))
            abort();
    }
}
void anti::c_proc::work()
{
    VMProtectBeginMutation("proc");
    auto procs = this->get(); if (procs.empty())
    {
        abort();
    }
    static auto blacklist_procname = std::vector<std::string>() = { xorstr_("CrySearch") , xorstr_("x64dbg") , xorstr_("pe-sieve"), xorstr_("PowerTool"), xorstr_("windbg"), xorstr_("DebugView"), xorstr_("Process Hacker") };
    static auto blacklist_title = std::vector<std::string>() = { xorstr_("Cheat Engine") , xorstr_("Cheat - Engine") , xorstr_("CrySearch") , xorstr_("x64dbg") , xorstr_("ollydbg") , xorstr_("PE Tools"), xorstr_("PowerTool"), xorstr_("DbgView"), xorstr_("Dbgview"),  xorstr_("\"\DESKTOP"), xorstr_("(local)") };
    for (auto obj : procs) this->scan(blacklist_procname, blacklist_title, obj, 0);
    VMProtectEnd();
}
bool anti::c_proc::stealththrd(HANDLE hThread)
{
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
    NTSTATUS Status;

    pNtSetInformationThread NtSIT = (pNtSetInformationThread)GetProcAddress(GetModuleHandle(xorstr_("ntdll.dll")), xorstr_("NtSetInformationThread"));

    if (NtSIT == NULL) return false;
    if (hThread == NULL) Status = NtSIT(GetCurrentThread(), 0x11, 0, 0);
    else Status = NtSIT(hThread, 0x11, 0, 0);
    if (Status != 0x00000000) return false;
    else return true;
}
anti::c_proc* anti::p_proc;