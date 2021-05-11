#include "run_elevation.hpp"
#include "run_firewall.hpp"
#include "run_networkisolation.hpp"

#include <iostream>

int main()
{
    try
    {
        auto & out = std::wcout;
        jb::run_elevation(out);
        jb::run_firewall(out);
        jb::run_networkisolation(out);
    }
    catch (std::exception const & e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "ERROR: Unknown" << std::endl;
        return 1;
    }

    return 0;
}
