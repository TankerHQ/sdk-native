#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>

using Tanker::Trustchain::UserId;

namespace Tanker
{
namespace Identity
{
std::vector<uint8_t> userSecretHash(gsl::span<uint8_t const> secretRand, UserId const& userId)
{
  if (secretRand.size() != USER_SECRET_SIZE - 1)
    throw Errors::AssertionError("invalid secretRand size");

  std::vector<uint8_t> input;
  input.insert(input.end(), secretRand.begin(), secretRand.end());
  input.insert(input.end(), userId.begin(), userId.end());
  return Tanker::Crypto::generichash16(input);
}

Crypto::SymmetricKey generateUserSecret(UserId const& userId)
{
  Crypto::SymmetricKey random;
  auto sp = gsl::make_span(random.data(), random.size() - 1);
  Crypto::randomFill(sp);
  auto check = userSecretHash(sp, userId);
  random.back() = check[0];
  return random;
}
}
}
