#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace detail
{
struct TrustchainIdImpl;
}
}

namespace Crypto
{
extern template class BasicHash<Trustchain::detail::TrustchainIdImpl>;
}

namespace Trustchain
{
using TrustchainId = Crypto::BasicHash<detail::TrustchainIdImpl>;
}
}
