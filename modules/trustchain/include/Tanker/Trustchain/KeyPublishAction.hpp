#pragma once

#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <boost/variant2/variant.hpp>
#include <gsl/gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Tanker::Trustchain
{
using KeyPublishAction = boost::variant2::
    variant<Actions::KeyPublishToUser, Actions::KeyPublishToUserGroup, Actions::KeyPublishToProvisionalUser>;

Crypto::Hash getHash(KeyPublishAction const& action);
Actions::Nature getNature(KeyPublishAction const& action);
Crypto::Hash const& getAuthor(KeyPublishAction const& action);
Crypto::Signature const& getSignature(KeyPublishAction const& action);

KeyPublishAction deserializeKeyPublishAction(gsl::span<std::uint8_t const>);
}
