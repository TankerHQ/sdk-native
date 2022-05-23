#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker::Trustchain::detail
{
struct HashedE2ePassphraseImpl;
}

namespace Tanker::Crypto
{
extern template class BasicHash<Trustchain::detail::HashedE2ePassphraseImpl>;
}

namespace Tanker::Trustchain
{
using HashedE2ePassphrase = Crypto::BasicHash<detail::HashedE2ePassphraseImpl>;
}
