#pragma once

#include <Tanker/Groups/IRequester.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class GroupRequesterStub
  : public trompeloeil::mock_interface<Groups::IRequester>
{
public:
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 std::vector<Trustchain::GroupId> const&),
             override);
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 Crypto::PublicEncryptionKey const&),
             override);
};
}