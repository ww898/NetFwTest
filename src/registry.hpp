#pragma once

#include <filesystem>
#include <stdexcept>
#include <vector>
#include <memory>
#include <optional>

#include <winreg.h>
#include <shlwapi.h>

namespace jb {

namespace detail_registry {

inline wchar_t const * reg_value_SZ(std::vector<uint8_t> & data)
{
    auto const count = data.size() / sizeof(wchar_t);
    if (!count)
        throw std::runtime_error("Empty string buffer size");
    auto const ptr = reinterpret_cast<wchar_t *>(data.data());
    ptr[count - 1] = L'\0';
    return ptr;
}

inline uint32_t reg_value_DWORD(std::vector<uint8_t> & data)
{
    if (data.size() < sizeof(uint32_t))
        throw std::runtime_error("Too small DWORD buffer size");
    return *reinterpret_cast<uint32_t const *>(data.data());
}

inline uint64_t reg_value_QWORD(std::vector<uint8_t> & data)
{
    if (data.size() < sizeof(uint64_t))
        throw std::runtime_error("Too small QWORD buffer size");
    return *reinterpret_cast<uint64_t const *>(data.data());
}

inline GUID reg_value_GUID(std::vector<uint8_t> & data)
{
    if (data.size() < sizeof(GUID))
        throw std::runtime_error("Too small GUID buffer size");
    return *reinterpret_cast<GUID const *>(data.data());
}

template<typename Dummy>
struct reg_key
{
    reg_key() :
        key_(nullptr, deleter_normal())
    {
    }

    reg_key(reg_key const & right) = default;
    reg_key & operator=(reg_key const & right) = default;

    void swap(reg_key & right) noexcept
    {
        key_.swap(right.key_);
        path_.swap(right.path_);
    }

    reg_key(reg_key && right) noexcept :
        key_(nullptr, deleter_normal())
    {
        swap(right);
    }

    reg_key & operator=(reg_key && right) noexcept
    {
        reg_key tmp;
        swap(tmp);
        swap(right);
        return *this;
    }

    #define KEY(N, K, T) \
        static reg_key const & N() \
        { \
            static reg_key<Dummy> const root_key(L###T, (K), root_reg_key_t()); \
            return root_key; \
        }
    #include "root_keys.inc"

    bool empty() const noexcept { return !key_; }
    explicit operator bool() const noexcept { return !!key_; }
    bool operator!() const noexcept { return !key_; }

    std::filesystem::path const & path() const { return path_; }

    reg_key create_key(std::wstring_view const & path, REGSAM const sam = KEY_ALL_ACCESS) const
    {
        auto const result_path = path_ / path.data();
        HKEY hkey = nullptr;
        auto const error = RegCreateKeyExW(key_.get(), path.data(), 0, nullptr, 0, sam, nullptr, &hkey, nullptr);
        if (error != ERROR_SUCCESS)
            throw std::runtime_error("Failed to create registry key");
        return reg_key(result_path, hkey);
    }

    reg_key open_key(std::wstring_view const & path, bool const throw_if_nof_found = true, REGSAM const sam = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS) const
    {
        auto const result_path = path_ / path.data();
        HKEY hkey = nullptr;
        auto const error = RegOpenKeyExW(key_.get(), path.data(), 0, sam, &hkey);
        if (error != ERROR_SUCCESS)
        {
            if (!throw_if_nof_found && error == ERROR_FILE_NOT_FOUND)
                return reg_key(result_path);
            throw std::runtime_error("Failed to open registry key");
        }
        return reg_key(result_path, hkey);
    }

    bool delete_key(std::wstring_view const & path, bool const throw_if_nof_found = true) const
    {
        auto const result_path = path_ / path.data();
        auto const error = SHDeleteKeyW(key_.get(), path.data());
        if (error == ERROR_SUCCESS)
            return true;
        if (!throw_if_nof_found && error == ERROR_FILE_NOT_FOUND)
            return false;
        throw std::runtime_error("Can't delete registry key");
    }

    void delete_value(std::wstring_view const & name) const
    {
        auto const error = RegDeleteValueW(key_.get(), name.data());
        if (error != ERROR_SUCCESS)
            throw std::runtime_error("Failed to delete registry value");
    }

    std::vector<std::wstring> get_key_names() const
    {
        std::vector<std::wstring> result;
        std::vector<wchar_t> name;
        name.resize(init_name_size);
        for (DWORD n = 0; ; ++n)
            while (true)
            {
                auto name_size = static_cast<DWORD>(name.size());
                auto const error = RegEnumKeyExW(key_.get(), n, name.empty() ? nullptr : name.data(), &name_size, nullptr, nullptr, nullptr, nullptr);
                if (error == ERROR_SUCCESS)
                {
                    result.push_back(name.data());
                    break;
                }
                if (error == ERROR_NO_MORE_ITEMS)
                    return result;
                if (error == ERROR_MORE_DATA)
                {
                    name.resize(2 * name_size);
                    continue;
                }
                throw std::runtime_error("Can't enum registry key names");
            }
    }

    std::vector<std::wstring> get_value_names() const
    {
        std::vector<std::wstring> result;
        std::vector<wchar_t> name;
        name.resize(init_name_size);
        for (DWORD n = 0; ; ++n)
            while (true)
            {
                auto name_size = static_cast<DWORD>(name.size());
                auto const error = RegEnumValueW(key_.get(), n, name.empty() ? nullptr : name.data(), &name_size, nullptr, nullptr, nullptr, nullptr);
                if (error == ERROR_SUCCESS)
                {
                    result.push_back(name.data());
                    break;
                }
                if (error == ERROR_NO_MORE_ITEMS)
                    return result;
                if (error == ERROR_MORE_DATA)
                {
                    name.resize(name_size);
                    continue;
                }
                throw std::runtime_error("Can't enum registry value names");
            }
    }

    void set_value(std::wstring_view const & name, DWORD const type, size_t const data_size, uint8_t const * const data) const
    {
        auto const error = RegSetValueExW(key_.get(), name.data(), 0, type, data, static_cast<DWORD>(data_size));
        if (error != ERROR_SUCCESS)
            throw std::runtime_error("Can't set registry value");
    }

    uint32_t get_value(std::wstring_view const & name, std::vector<uint8_t> & data, bool const throw_if_nof_found = true) const
    {
        data.resize(init_data_size);
        while (true)
        {
            DWORD type;
            auto data_size = static_cast<DWORD>(data.size());
            auto const error = RegQueryValueExW(key_.get(), name.data(), nullptr, &type, data.empty() ? nullptr : data.data(), &data_size);
            if (error == ERROR_SUCCESS)
            {
                data.resize(data_size);
                return type;
            }
            if (!throw_if_nof_found && error == ERROR_FILE_NOT_FOUND)
            {
                data.clear();
                return REG_NONE;
            }
            if (error == ERROR_MORE_DATA)
            {
                data.resize(data_size);
                continue;
            }
            throw std::runtime_error("Can't get registry value");
        }
    }

    void set_value_SZ(std::wstring_view const & name, std::wstring_view const & value, DWORD const type = REG_SZ) const
    {
        if (!(type == REG_SZ || type == REG_EXPAND_SZ))
            throw std::runtime_error("Invalid type");
        set_value(name, type, (value.size() + 1) * sizeof(wchar_t), reinterpret_cast<uint8_t const *>(value.data()));
    }

    void set_value_DWORD(std::wstring_view const & name, uint32_t const value) const
    {
        set_value(name, REG_DWORD, sizeof(value), reinterpret_cast<uint8_t const *>(&value));
    }

    void set_value_QWORD(std::wstring_view const & name, uint64_t const value) const
    {
        set_value(name, REG_QWORD, sizeof(value), reinterpret_cast<uint8_t const *>(&value));
    }

    bool get_value_SZ(std::wstring_view const & name, std::wstring & value, bool const throw_if_nof_found = true) const
    {
        std::vector<uint8_t> data;
        auto const type = get_value(name, data, throw_if_nof_found);
        switch (type)
        {
        case REG_NONE:
            return false;
        case REG_EXPAND_SZ:
        case REG_SZ:
            value = reg_value_SZ(data);
            return true;
        default:
            throw std::runtime_error("Expected REG_SZ or REG_EXPAND_SZ registry value type");
        }
    }

    std::wstring get_value_SZ(std::wstring_view const & name) const
    {
        std::wstring value;
        get_value_SZ(name, value);
        return value;
    }

    std::optional<std::wstring> get_value_SZ(std::wstring_view const & name, bool const throw_if_nof_found) const
    {
        std::wstring value;
        if (!get_value_SZ(name, value, throw_if_nof_found))
            return std::nullopt;
        return value;
    }

    bool get_value_DWORD(std::wstring_view const & name, uint32_t & value, bool const throw_if_nof_found = true) const
    {
        std::vector<uint8_t> data;
        auto const type = get_value(name, data, throw_if_nof_found);
        switch (type)
        {
        case REG_NONE:
            return false;
        case REG_DWORD:
            value = reg_value_DWORD(data);
            return true;
        default:
            throw std::runtime_error("Expected REG_DWORD registry value type");
        }
    }

    uint32_t get_value_DWORD(std::wstring_view const & name) const
    {
        uint32_t value;
        get_value_DWORD(name, value);
        return value;
    }

    std::optional<uint32_t> get_value_DWORD(std::wstring_view const & name, bool const throw_if_nof_found) const
    {
        uint32_t value;
        if (!get_value_DWORD(name, value, throw_if_nof_found))
            return std::nullopt;
        return value;
    }

    bool get_value_QWORD(std::wstring_view const & name, uint64_t & value, bool const throw_if_nof_found = true) const
    {
        std::vector<uint8_t> data;
        auto const type = get_value(name, data, throw_if_nof_found);
        switch (type)
        {
        case REG_NONE:
            return false;
        case REG_QWORD:
            value = reg_value_QWORD(data);
            return true;
        default:
            throw std::runtime_error("Expected REG_QWORD registry value type");
        }
    }

    uint64_t get_value_QWORD(std::wstring_view const & name) const
    {
        uint64_t value;
        get_value_QWORD(name, value);
        return value;
    }

    std::optional<uint64_t> get_value_QWORD(std::wstring_view const & name, bool const throw_if_nof_found) const
    {
        uint64_t value;
        if (!get_value_QWORD(name, value, throw_if_nof_found))
            return std::nullopt;
        return value;
    }

private:
    reg_key(std::filesystem::path const & path, HKEY const hkey = nullptr) :
        key_(hkey, deleter_normal()),
        path_(path)
    {
    }

    struct root_reg_key_t {};

    reg_key(wchar_t const * const path, HKEY const hkey, root_reg_key_t const) :
        key_(hkey, deleter_empty()),
        path_(path)
    {
    }

    struct deleter_normal { void operator()(HKEY handle) const noexcept { RegCloseKey(handle); } };
    struct deleter_empty { void operator()(HKEY) const noexcept {} };

    std::shared_ptr<std::remove_pointer_t<HKEY>> key_;
    std::filesystem::path path_;

    static DWORD const init_name_size = 32;
    static DWORD const grow_name_size = 16;
    static DWORD const init_data_size = sizeof(GUID);
};

}

using reg_key = detail_registry::reg_key<void>;

}
