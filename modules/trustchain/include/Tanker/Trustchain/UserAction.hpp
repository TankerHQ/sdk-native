#pragma once

#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <boost/variant2/variant.hpp>
#include <gsl/gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Tanker::Trustchain
{
using UserAction = boost::variant2::variant<Actions::DeviceCreation,
                                            Actions::DeviceRevocation>;

Crypto::Hash getHash(UserAction const& action);
Actions::Nature getNature(UserAction const& action);
Crypto::Hash const& getAuthor(UserAction const& action);
Crypto::Signature const& getSignature(UserAction const& action);

UserAction deserializeUserAction(gsl::span<std::uint8_t const>);
}
