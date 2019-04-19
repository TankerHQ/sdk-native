#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace detail
{
struct DeviceIdImpl;
}
}

namespace Crypto
{
extern template class BasicHash<Trustchain::detail::DeviceIdImpl>;
}

namespace Trustchain
{
using DeviceId = Crypto::BasicHash<detail::DeviceIdImpl>;
}
}

