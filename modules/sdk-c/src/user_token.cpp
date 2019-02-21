#include <ctanker/user_token.h>

#include <Tanker/Identity/UserToken.hpp>

#include <tconcurrent/async.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

tanker_expected_t* tanker_generate_user_token(
    b64char const* trustchain_id,
    b64char const* trustchain_private_key,
    char const* user_id)
{
  return makeFuture(tc::sync([&] {
    return static_cast<void*>(
        duplicateString(Tanker::Identity::generateUserToken(
            trustchain_id, trustchain_private_key, Tanker::SUserId{user_id})));
  }));
}
