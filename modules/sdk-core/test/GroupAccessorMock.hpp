#pragma once

#include <Tanker/Groups/IAccessor.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class GroupAccessorMock : public Groups::IAccessor
{
public:
  MAKE_MOCK1(getInternalGroups,
             tc::cotask<InternalGroupPullResult>(
                 std::vector<Trustchain::GroupId> const&),
             override);
  MAKE_MOCK1(getInternalGroupsAndMembers,
             tc::cotask<InternalGroupAndMembersPullResult>(
                 std::vector<Trustchain::GroupId> const&),
             override);
  MAKE_MOCK1(getPublicEncryptionKeys,
             tc::cotask<PublicEncryptionKeyPullResult>(
                 std::vector<Trustchain::GroupId> const&),
             override);
  MAKE_MOCK1(getEncryptionKeyPair,
             tc::cotask<std::optional<Crypto::EncryptionKeyPair>>(
                 Crypto::PublicEncryptionKey const&),
             override);
};
}
