#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cstddef>
#include <tuple>
#include <type_traits>

namespace Tanker::Trustchain
{
class Context
{
public:
  Context() = default;
  Context(TrustchainId const& id,
          Crypto::PublicSignatureKey const& publicSignatureKey);

  TrustchainId const& id() const;
  Crypto::PublicSignatureKey const& publicSignatureKey() const;

private:
  TrustchainId _id;
  Crypto::PublicSignatureKey _publicSignatureKey;
};

bool operator==(Context const& lhs, Context const& rhs);
bool operator!=(Context const& lhs, Context const& rhs);

template <std::size_t I>
auto const& get(Context const& c)
{
  if constexpr (I == 0)
    return c.id();
  else
    return c.publicSignatureKey();
}
}

namespace std
{
template <>
class tuple_size<::Tanker::Trustchain::Context>
  : public std::integral_constant<std::size_t, 2>
{
};

template <>
class tuple_element<0, ::Tanker::Trustchain::Context>
{
public:
  using type = ::Tanker::Trustchain::TrustchainId const&;
};

template <>
class tuple_element<1, ::Tanker::Trustchain::Context>
{
public:
  using type = ::Tanker::Crypto::PublicSignatureKey const&;
};
}
