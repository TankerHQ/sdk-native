#pragma once

#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationKey.hpp>

#include <optional.hpp>

namespace Tanker
{
namespace Unlock
{
namespace detail
{
template <typename... Opt>
using OptTuple = std::tuple<nonstd::optional<Opt>...>;

template <typename Base>
struct OptionsBase : private Base
{
  using Base::Base;

  template <typename T>
  nonstd::optional<T> const& get() const&
  {
    return std::get<nonstd::optional<T>>(*this);
  }

  template <typename T>
  OptionsBase& set(T const& l)
  {
    std::get<nonstd::optional<T>>(*this) = l;
    return *this;
  }

  template <typename T>
  OptionsBase& set(T&& l)
  {
    std::get<nonstd::optional<T>>(*this) = std::move(l);
    return *this;
  }

  template <typename T>
  OptionsBase& reset() noexcept
  {
    std::get<nonstd::optional<T>>(*this).reset();
    return *this;
  }
};
}

using UpdateOptions =
    detail::OptionsBase<detail::OptTuple<Email, Password, VerificationKey>>;
using CreationOptions = detail::OptionsBase<detail::OptTuple<Email, Password>>;
using RegistrationOptions =
    detail::OptionsBase<detail::OptTuple<Email, Password>>;
}
}
