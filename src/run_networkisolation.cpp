#include "config.hpp"

#include "run_networkisolation.hpp"
#include "on_exit.hpp"

#include <iomanip>
#include <networkisolation.h>
#include <sddl.h>


namespace jb {

namespace {

bool is_succeeded(std::wostream & out, DWORD const error)
{
    if (error == ERROR_SUCCESS)
        return true;
    out << L"failed: 0x" << std::hex << std::uppercase << std::setw(2 * sizeof error) << std::setfill(L'0') << error << std::endl;
    return false;
}

void check_NetworkIsolationDiagnoseConnectFailure(std::wostream & out, LPCWSTR const host)
{
    out << L"NetworkIsolationDiagnoseConnectFailureAndGetInfo: '" << host << L"': ";
    NETISO_ERROR_TYPE type;
    if (is_succeeded(out, NetworkIsolationDiagnoseConnectFailureAndGetInfo(host, &type)))
        out << (
            type == NETISO_ERROR_TYPE_NONE                   ? L"none"                   :
            type == NETISO_ERROR_TYPE_PRIVATE_NETWORK        ? L"private"                :
            type == NETISO_ERROR_TYPE_INTERNET_CLIENT        ? L"internet_client"        :
            type == NETISO_ERROR_TYPE_INTERNET_CLIENT_SERVER ? L"internet_client_server" : L"???") << std::endl;
}

void check_NetworkIsolationEnumAppContainers(std::wostream & out, DWORD const flags)
{
    out << L"NetworkIsolationEnumAppContainers: 0x" << std::hex << std::uppercase << std::setw(2 * sizeof flags) << std::setfill(L'0') << flags << L": ";
    DWORD size;
    PINET_FIREWALL_APP_CONTAINER ptr;
    if (is_succeeded(out, NetworkIsolationEnumAppContainers(flags, &size, &ptr)))
    {
        auto && free_ptr = make_on_exit_scope([ptr] { NetworkIsolationFreeAppContainers(ptr); });
        out << std::dec << size << ":" << std::endl;
        for (DWORD n = 0; n < size; ++n)
        {
            out << L"  #" << std::dec << n << L": ";
            LPWSTR str;
            if (is_succeeded(out, ConvertSidToStringSidW(ptr[n].appContainerSid, &str) ? ERROR_SUCCESS : GetLastError()))
            {
                auto && free_str = make_on_exit_scope([str] { LocalFree(str); });
                out << str << L": " << ptr[n].appContainerName << std::endl;
            }
        }
    }
}

void check_NetworkIsolationGetAppContainerConfig(std::wostream & out)
{
    out << L"NetworkIsolationGetAppContainerConfig: ";
    DWORD size;
    PSID_AND_ATTRIBUTES ptr;
    if (is_succeeded(out, NetworkIsolationGetAppContainerConfig(&size, &ptr)))
    {
        auto && free_ptr = make_on_exit_scope([ptr, size]
            {
                for (auto n = size; n-- > 0; )
                    HeapFree(GetProcessHeap(), 0, ptr[n].Sid);
                HeapFree(GetProcessHeap(), 0, ptr);
            });

        out << std::dec << size << ":" << std::endl;
        for (DWORD n = 0; n < size; ++n)
        {
            out << L"  #" << std::dec << n << L": ";
            LPWSTR str;
            if (is_succeeded(out, ConvertSidToStringSidW(ptr[n].Sid, &str) ? ERROR_SUCCESS : GetLastError()))
            {
                auto && free_str = make_on_exit_scope([str] { LocalFree(str); });
                out << str << L": 0x" << std::hex << std::uppercase << std::setw(2 * sizeof ptr[n].Attributes) << std::setfill(L'0') << ptr[n].Attributes<< std::endl;
            }
        }

    }
}

}

void run_networkisolation(std::wostream & out)
{
    check_NetworkIsolationDiagnoseConnectFailure(out, L"127.0.0.1");
    check_NetworkIsolationDiagnoseConnectFailure(out, L"::1");
    check_NetworkIsolationDiagnoseConnectFailure(out, L"localhost");

    check_NetworkIsolationEnumAppContainers(out, 0);
    check_NetworkIsolationEnumAppContainers(out, NETISO_FLAG_FORCE_COMPUTE_BINARIES);

    check_NetworkIsolationGetAppContainerConfig(out);
}

}