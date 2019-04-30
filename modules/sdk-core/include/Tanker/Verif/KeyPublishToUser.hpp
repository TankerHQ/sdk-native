#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct User;

namespace Verif
{
void verifyKeyPublishToUser(Trustchain::ServerEntry const& serverEntry,
                            Device const& author);
}
}
