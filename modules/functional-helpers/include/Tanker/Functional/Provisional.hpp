#pragma once

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/Device.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>

#include <tconcurrent/coroutine.hpp>

#include <boost/variant2/variant.hpp>

namespace Tanker::Functional
{
struct AppProvisionalUser
{
  boost::variant2::variant<Email, PhoneNumber> value;
  SSecretProvisionalIdentity secretIdentity;
  SPublicIdentity publicIdentity;
};

void to_json(nlohmann::json& j, AppProvisionalUser const& user);
void from_json(nlohmann::json const& j, AppProvisionalUser& user);
}
