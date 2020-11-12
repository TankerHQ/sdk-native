#pragma once

#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/Actions/UserGroupUpdate.hpp>

#include <boost/variant2/variant.hpp>
#include <gsl/gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Tanker::Trustchain
{
using GroupAction = boost::variant2::variant<Actions::UserGroupAddition,
                                             Actions::UserGroupCreation,
                                             Actions::UserGroupUpdate>;

Crypto::Hash getHash(GroupAction const& action);
Actions::Nature getNature(GroupAction const& action);
Crypto::Hash const& getAuthor(GroupAction const& action);
Crypto::Signature const& getSignature(GroupAction const& action);

GroupAction deserializeGroupAction(gsl::span<std::uint8_t const>);
}
