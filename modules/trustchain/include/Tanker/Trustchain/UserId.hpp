#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace detail
{
struct UserIdImpl;
}
}

namespace Crypto
{
extern template class BasicHash<Trustchain::detail::UserIdImpl>;
}

namespace Trustchain
{
using UserId = Crypto::BasicHash<detail::UserIdImpl>;
}
}
