#pragma once

#include <type_traits>
#include <utility>

namespace jb {

template<typename Fn>
struct on_exit_scope final
{
    template<typename Fn1>
    on_exit_scope(Fn1 && fn) :
        fn_(std::forward<Fn1>(fn))
    {
    }

    on_exit_scope(on_exit_scope const &) = delete;
    on_exit_scope & operator=(on_exit_scope const &) = delete;

    on_exit_scope(on_exit_scope &&) = delete;
    on_exit_scope & operator=(on_exit_scope &&) = delete;

    ~on_exit_scope()
    {
        try
        {
            std::move(fn_)();
        }
        catch (...)
        {
        }
    }

private:
    Fn fn_;
};

template<typename Fn>
on_exit_scope<std::decay_t<Fn>> make_on_exit_scope(Fn && fn)
{
    return{ std::forward<Fn>(fn) };
}

}
