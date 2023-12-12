#pragma once

#include <Tanker/Groups/IRequester.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class GroupRequesterStub : public trompeloeil::mock_interface<Groups::IRequester>
{
public:
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::GroupAction>>(gsl::span<Trustchain::GroupId const>),
             override);
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::GroupAction>>(Crypto::PublicEncryptionKey const&),
             override);
  MAKE_MOCK1(createGroup, tc::cotask<void>(Trustchain::Actions::UserGroupCreation const&), override);
  MAKE_MOCK1(updateGroup, tc::cotask<void>(Trustchain::Actions::UserGroupAddition const&), override);
  MAKE_MOCK2(softUpdateGroup,
             tc::cotask<void>(Trustchain::Actions::UserGroupRemoval const& groupRemoval,
                              std::optional<Trustchain::Actions::UserGroupAddition> const& groupAddition),
             override);
};
}
