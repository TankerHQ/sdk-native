#pragma once

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

#include <vector>

namespace Tanker
{
struct PartitionedIdentities
{
  std::vector<Trustchain::UserId> userIds;
  std::vector<Identity::PublicProvisionalIdentity> publicProvisionalIdentities;
};

std::vector<Identity::PublicIdentity> extractPublicIdentities(
    std::vector<SPublicIdentity> const& spublicIdentities);

PartitionedIdentities partitionIdentities(
    std::vector<Identity::PublicIdentity> const& identities);

std::vector<SPublicIdentity> mapIdentitiesToStrings(
    std::vector<Trustchain::UserId> const& errorIds,
    std::vector<SPublicIdentity> const& sIds,
    std::vector<Identity::PublicIdentity> const& ids);
}
