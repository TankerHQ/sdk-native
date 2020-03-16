#include <Tanker/Users/LocalUser.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>

#include <fmt/format.h>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(LocalUser);

namespace Tanker::Users
{
LocalUser::LocalUser(Trustchain::UserId const& userId,
                     Trustchain::DeviceId const& deviceId,
                     DeviceKeys const& deviceKeys,
                     gsl::span<Crypto::EncryptionKeyPair const> userKeys)
  : _userId(userId),
    _deviceId(deviceId),
    _deviceKeys(deviceKeys),
    _userKeys(userKeys.begin(), userKeys.end())
{
}

Trustchain::DeviceId const& LocalUser::deviceId() const
{
  return _deviceId;
}

DeviceKeys const& LocalUser::deviceKeys() const
{
  return _deviceKeys;
}

Trustchain::UserId const& LocalUser::userId() const
{
  return _userId;
}

std::vector<Crypto::EncryptionKeyPair> const& LocalUser::userKeys() const
{
  return _userKeys;
}

std::optional<Crypto::EncryptionKeyPair> LocalUser::findKeyPair(
    Crypto::PublicEncryptionKey const& publicKey) const
{

  if (auto it = std::find_if(
          std::begin(_userKeys),
          std::end(_userKeys),
          [&](auto const& kp) { return kp.publicKey == publicKey; });
      it != std::end(_userKeys))
    return *it;
  else
    return std::nullopt;
}

Crypto::EncryptionKeyPair LocalUser::currentKeyPair() const
{
  return _userKeys.back();
}
}
