#pragma once

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ProvisionalUserId.hpp>
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

Identity::PublicIdentity extractPublicIdentity(
    SPublicIdentity const& spublicIdentity);

PartitionedIdentities partitionIdentities(
    std::vector<Identity::PublicIdentity> const& identities);

std::vector<SPublicIdentity> mapIdentitiesToStrings(
    std::vector<Trustchain::UserId> const& errorIds,
    std::vector<SPublicIdentity> const& sIds,
    std::vector<Identity::PublicIdentity> const& ids);

std::vector<SPublicIdentity> mapIdentitiesToStrings(
    std::vector<Trustchain::ProvisionalUserId> const& errorUsers,
    std::vector<SPublicIdentity> const& sIds,
    std::vector<Identity::PublicIdentity> const& ids);
}
