#pragma once

#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <cstdint>

namespace Tanker
{
Trustchain::ServerEntry clientToServerEntry(Trustchain::ClientEntry const& e,
                                            std::uint64_t index = 0);
}
