#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct ExternalGroup;

namespace Verif
{
void verifyKeyPublishToUserGroup(Trustchain::ServerEntry const& serverEntry,
                                 Device const& author,
                                 ExternalGroup const& recipientGroup);
}
}
