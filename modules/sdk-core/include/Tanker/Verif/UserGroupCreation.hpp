#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct Device;

namespace Verif
{
void verifyUserGroupCreation(UnverifiedEntry const& entry,
                             Device const& author);
}
}
