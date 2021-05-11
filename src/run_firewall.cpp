#include "config.hpp"

#include "run_firewall.hpp"
#include "on_exit.hpp"

#include <iomanip>

#include <netfw.h>

namespace jb
{

namespace
{

bool is_succeeded(std::wostream & out, HRESULT const hr)
{
    if (SUCCEEDED(hr))
        return true;
    out << L"failed: 0x" << std::hex << std::uppercase << std::setw(2 * sizeof hr) << std::setfill(L'0') << hr << std::endl;
    return false;
}

template <typename Fn>
void check_VARIANT_BOOL(std::wostream & out, LPCWSTR const name, Fn && fn)
{
    out << L"  " << name << L": ";
    VARIANT_BOOL is_enabled;
    if (is_succeeded(out, std::forward<Fn>(fn)(&is_enabled)))
        out << (is_enabled ? L"enabled" : L"disabled") << std::endl;
}

template <typename Fn>
void check_NET_FW_ACTION(std::wostream & out, LPCWSTR const name, Fn && fn)
{
    out << L"  " << name << L": ";
    NET_FW_ACTION action;
    if (is_succeeded(out, std::forward<Fn>(fn)(&action)))
        out << (
            action == NET_FW_ACTION_BLOCK ? L"block" :
            action == NET_FW_ACTION_ALLOW ? L"allow" : L"???") << std::endl;
}

void check_profile(std::wostream & out, INetFwPolicy2 * const net_fw_policy2, NET_FW_PROFILE_TYPE2 const net_fw_profile_type2)
{
    out << L"FirewallProfileType:" <<
        (net_fw_profile_type2 & NET_FW_PROFILE2_PUBLIC  ? L" public"  : L"") <<
        (net_fw_profile_type2 & NET_FW_PROFILE2_DOMAIN  ? L" domain"  : L"") <<
        (net_fw_profile_type2 & NET_FW_PROFILE2_PRIVATE ? L" private" : L"") << std::endl;

    check_VARIANT_BOOL(out, L"FirewallEnabled"                             , [=](auto is_enabled) { return net_fw_policy2->get_FirewallEnabled                             (net_fw_profile_type2, is_enabled); });
    check_VARIANT_BOOL(out, L"BlockAllInboundTraffic"                      , [=](auto is_enabled) { return net_fw_policy2->get_BlockAllInboundTraffic                      (net_fw_profile_type2, is_enabled); });
    check_VARIANT_BOOL(out, L"NotificationsDisabled"                       , [=](auto is_enabled) { return net_fw_policy2->get_NotificationsDisabled                       (net_fw_profile_type2, is_enabled); });
    check_VARIANT_BOOL(out, L"UnicastResponsesToMulticastBroadcastDisabled", [=](auto is_enabled) { return net_fw_policy2->get_UnicastResponsesToMulticastBroadcastDisabled(net_fw_profile_type2, is_enabled); });

    check_NET_FW_ACTION(out, L"DefaultInboundAction" , [=](auto action) { return net_fw_policy2->get_DefaultInboundAction (net_fw_profile_type2, action); });
    check_NET_FW_ACTION(out, L"DefaultOutboundAction", [=](auto action) { return net_fw_policy2->get_DefaultOutboundAction(net_fw_profile_type2, action); });
}
}

void run_firewall(std::wostream & out)
{
    out << L"CoInitializeEx: ";
    if (is_succeeded(out, CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)))
    {
        auto && free_com = make_on_exit_scope([&]
            {
                CoUninitialize();
                out << L"CoUninitialize: succeeded" << std::endl;
            });
        out << L"succeeded" << std::endl;

        out << L"CoCreateInstance: INetFwPolicy2: ";
        INetFwPolicy2 * net_fw_policy2;
        if (is_succeeded(out, CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&net_fw_policy2))))
        {
            auto && free_net_fw_policy2 = make_on_exit_scope([&]
                {
                    net_fw_policy2->Release();
                    net_fw_policy2 = nullptr;
                    out << L"INetFwPolicy2: released" << std::endl;
                });
            out << L"succeeded" << std::endl;

            check_profile(out, net_fw_policy2, NET_FW_PROFILE2_PRIVATE);
            check_profile(out, net_fw_policy2, NET_FW_PROFILE2_DOMAIN );
            check_profile(out, net_fw_policy2, NET_FW_PROFILE2_PUBLIC );
        }
    }
}
}
