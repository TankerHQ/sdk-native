#include <ctanker/identity.h>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <tconcurrent/async.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

tanker_expected_t* tanker_create_identity(b64char const* trustchain_id,
                                          b64char const* trustchain_private_key,
                                          char const* user_id)
{
  return makeFuture(tc::sync([&] {
    return static_cast<void*>(duplicateString(Tanker::Identity::createIdentity(
        trustchain_id, trustchain_private_key, Tanker::SUserId{user_id})));
  }));
}

tanker_expected_t* tanker_create_provisional_identity(
    b64char const* trustchain_id, char const* email)
{
  return makeFuture(tc::sync([&] {
    return static_cast<void*>(
        duplicateString(Tanker::Identity::createProvisionalIdentity(
            trustchain_id, Tanker::Email{email})));
  }));
}

tanker_expected_t* tanker_upgrade_user_token(b64char const* trustchain_id,
                                             char const* user_id,
                                             b64char const* user_token)
{
  return makeFuture(tc::sync([&] {
    return static_cast<void*>(
        duplicateString(Tanker::Identity::upgradeUserToken(
            trustchain_id, Tanker::SUserId{user_id}, user_token)));
  }));
}

tanker_expected_t* tanker_get_public_identity(b64char const* identity)
{
  return makeFuture(tc::sync([&] {
    return static_cast<void*>(
        duplicateString(Tanker::Identity::getPublicIdentity(identity)));
  }));
}
