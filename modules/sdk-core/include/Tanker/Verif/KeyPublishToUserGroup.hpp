#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct Device;
struct ExternalGroup;

namespace Verif
{
void verifyKeyPublishToUserGroup(UnverifiedEntry const& entry,
                                 Device const& author,
                                 ExternalGroup const& recipientGroup);
}
}
