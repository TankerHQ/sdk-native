#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct Device;
struct ExternalGroup;

namespace Verif
{
void verifyUserGroupAddition(UnverifiedEntry const& entry,
                             Device const& author,
                             ExternalGroup const& group);
}
}
