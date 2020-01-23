#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <gsl-lite.hpp>

#include <cstddef>
#include <optional>
#include <tuple>
#include <type_traits>
#include <vector>

namespace Tanker::Users
{
class User
{
public:
  User() = default;
  User(Trustchain::UserId const& userId,
       std::optional<Crypto::PublicEncryptionKey> const& userKey,
       gsl::span<Device const> devices);

  void addDevice(Device const& device);
  void setUserKey(Crypto::PublicEncryptionKey const& userKey);

  std::optional<Device> findDevice(Trustchain::DeviceId const& deviceId) const;
  Device& getDevice(Trustchain::DeviceId const& deviceId);
  std::optional<Device> findDevice(
      Crypto::PublicEncryptionKey const& publicKey) const;

  Trustchain::UserId const& id() const;
  std::optional<Crypto::PublicEncryptionKey> const& userKey() const;
  std::vector<Device> const& devices() const;

private:
  Trustchain::UserId _id;
  std::optional<Crypto::PublicEncryptionKey> _userKey;
  std::vector<Device> _devices;
};

template <std::size_t I>
auto const& get(User const& u)
{
  if constexpr (I == 0)
    return u.id();
  else if constexpr (I == 1)
    return u.userKey();
  else
    return u.devices();
}

bool operator==(User const& l, User const& r);
bool operator!=(User const& l, User const& r);
bool operator<(User const& l, User const& r);
}

namespace std
{
template <>
class tuple_size<::Tanker::Users::User>
  : public std::integral_constant<std::size_t, 3>
{
};

template <>
class tuple_element<0, ::Tanker::Users::User>
{
public:
  using type = ::Tanker::Trustchain::UserId const&;
};

template <>
class tuple_element<1, ::Tanker::Users::User>
{
public:
  using type = std::optional<::Tanker::Crypto::PublicEncryptionKey> const&;
};

template <>
class tuple_element<2, ::Tanker::Users::User>
{
public:
  using type = std::vector<::Tanker::Users::Device> const&;
};
}
