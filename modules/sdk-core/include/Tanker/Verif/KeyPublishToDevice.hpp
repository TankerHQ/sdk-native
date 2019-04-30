#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct User;

namespace Verif
{
void verifyKeyPublishToDevice(Trustchain::ServerEntry const& serverEntry,
                              Device const& author,
                              User const& recipientUser);
}
}
