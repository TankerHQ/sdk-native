#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct Device;
struct User;

namespace Verif
{
void verifyKeyPublishToUser(UnverifiedEntry const& entry,
                            Device const& author,
                            User const& recipientUser);
}
}
