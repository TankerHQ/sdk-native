#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker::Trustchain::detail
{
struct HashedPassphraseImpl;
}

namespace Tanker::Crypto
{
extern template class BasicHash<Trustchain::detail::HashedPassphraseImpl>;
}

namespace Tanker::Trustchain
{
using HashedPassphrase = Crypto::BasicHash<detail::HashedPassphraseImpl>;
}