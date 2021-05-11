#include "config.hpp"

#include "run_elevation.hpp"

#include <iomanip>

#include "on_exit.hpp"

extern "C" {

#define ELEVATION_UAC_ENABLED                 0x1
#define ELEVATION_VIRTUALIZATION_ENABLED      0x2
#define ELEVATION_INSTALLER_DETECTION_ENABLED 0x4

NTSTATUS
    NTAPI
    RtlQueryElevationFlags(
        DWORD* pFlags
    );

}

namespace jb
{

namespace
{

bool is_succeeded(std::wostream & out, DWORD const error)
{
    if (error == ERROR_SUCCESS)
        return true;
    out << L"failed: 0x" << std::hex << std::uppercase << std::setw(2 * sizeof error) << std::setfill(L'0') << error << std::endl;
    return false;
}

}

void run_elevation(std::wostream & out)
{
    out << L"RtlQueryElevationFlags:";
    DWORD elevation;
    if (is_succeeded(out, RtlQueryElevationFlags(&elevation)))
    {
        if (elevation & ELEVATION_UAC_ENABLED)
            out << L" uac";
        if (elevation & ELEVATION_VIRTUALIZATION_ENABLED)
            out << L" virtualization";
        if (elevation & ELEVATION_INSTALLER_DETECTION_ENABLED)
            out << L" installer_detection";
        out << std::endl;
    }

    out << L"OpenProcessToken: ";
    HANDLE token;
    if (is_succeeded(out, OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) ? ERROR_SUCCESS : GetLastError()))
    {
        auto && free_handle = make_on_exit_scope([token] { CloseHandle(token); });
        out << L"GetTokenInformation: TokenElevationType: ";
        DWORD size;
        TOKEN_ELEVATION_TYPE token_elevation_type;
        if (is_succeeded(out, GetTokenInformation(token, TokenElevationType, &token_elevation_type, sizeof token_elevation_type, &size) ? ERROR_SUCCESS : GetLastError()))
            out << (
                token_elevation_type == TokenElevationTypeDefault ? L"default" :
                token_elevation_type == TokenElevationTypeLimited ? L"limited" :
                token_elevation_type == TokenElevationTypeFull    ? L"full"    : L"???") << std::endl;
    }
}

}