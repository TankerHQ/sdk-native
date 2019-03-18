#include <Tanker/Actions/DeviceCreation.hpp>

#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Identity/Delegation.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace
{
struct GhostDeviceVisitor
{
  template <typename T>
  constexpr bool operator()(T const&) const
  {
    return false;
  }

  bool operator()(DeviceCreation3 const& dc) const
  {
    return dc.isGhostDevice;
  }
};

struct UserKeyPairVisitor
{
  using type = nonstd::optional<UserKeyPair>;

  template <typename T>
  type operator()(T const&) const
  {
    return {};
  }

  type operator()(DeviceCreation3 const& dc) const
  {
    return dc.userKeyPair;
  }
};

template <typename T>
void deserializeDeviceCreationCommonFields(Serialization::SerializedSource& ss,
                                           T& dc)
{
  Serialization::deserialize(ss, dc.ephemeralPublicSignatureKey);
  Serialization::deserialize(ss, dc.userId);
  Serialization::deserialize(ss, dc.delegationSignature);
  Serialization::deserialize(ss, dc.publicSignatureKey);
  Serialization::deserialize(ss, dc.publicEncryptionKey);
}

template <typename T>
void jsonifyDeviceCreationCommonFields(nlohmann::json& j, T const& dc)
{
  j["ephemeralPublicSignatureKey"] = dc.ephemeralPublicSignatureKey;
  j["userId"] = dc.userId;
  j["delegationSignature"] = dc.delegationSignature;
  j["publicSignatureKey"] = dc.publicSignatureKey;
  j["publicEncryptionKey"] = dc.publicEncryptionKey;
}
}

DeviceCreation::DeviceCreation(variant_type&& v) : _v(std::move(v))
{
}

DeviceCreation::DeviceCreation(variant_type const& v) : _v(v)
{
}

DeviceCreation& DeviceCreation::operator=(variant_type&& v)
{
  _v = std::move(v);
  return *this;
}

DeviceCreation& DeviceCreation::operator=(variant_type const& v)
{
  _v = v;
  return *this;
}

auto DeviceCreation::variant() const -> variant_type const&
{
  return _v;
}

Nature DeviceCreation::nature() const
{
  return mpark::visit([](auto const& a) { return a.nature; }, _v);
}

Crypto::PublicSignatureKey const& DeviceCreation::ephemeralPublicSignatureKey()
    const
{
  return mpark::visit(
      [](auto const& a) -> Crypto::PublicSignatureKey const& {
        return a.ephemeralPublicSignatureKey;
      },
      _v);
}

UserId const& DeviceCreation::userId() const
{
  return mpark::visit([](auto const& a) -> UserId const& { return a.userId; },
                      _v);
}

Crypto::Signature const& DeviceCreation::delegationSignature() const
{
  return mpark::visit(
      [](auto const& a) -> Crypto::Signature const& {
        return a.delegationSignature;
      },
      _v);
}

Crypto::PublicSignatureKey const& DeviceCreation::publicSignatureKey() const
{
  return mpark::visit(
      [](auto const& a) -> Crypto::PublicSignatureKey const& {
        return a.publicSignatureKey;
      },
      _v);
}

Crypto::PublicEncryptionKey const& DeviceCreation::publicEncryptionKey() const
{
  return mpark::visit(
      [](auto const& a) -> Crypto::PublicEncryptionKey const& {
        return a.publicEncryptionKey;
      },
      _v);
}

bool DeviceCreation::isGhostDevice() const
{
  return mpark::visit(GhostDeviceVisitor{}, _v);
}

nonstd::optional<UserKeyPair> DeviceCreation::userKeyPair() const
{
  return mpark::visit(UserKeyPairVisitor{}, _v);
}

std::vector<Index> DeviceCreation::makeIndexes() const
{
  auto const& id = userId();
  auto const& key = publicSignatureKey();

  return {Index{IndexType::UserId, {id.begin(), id.end()}},
          Index{IndexType::DevicePublicSignatureKey, {key.begin(), key.end()}}};
}

DeviceCreation DeviceCreation::createV1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey)
{
  DeviceCreation1 dc{delegation.ephemeralKeyPair.publicKey,
                     delegation.userId,
                     delegation.signature,
                     signatureKey,
                     encryptionKey};
  return DeviceCreation{dc};
}

DeviceCreation DeviceCreation::createV3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKey,
    bool isGhostDevice)
{
  auto const encryptedUserKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKey.privateKey, encryptionKey);

  DeviceCreation3 dc{delegation.ephemeralKeyPair.publicKey,
                     delegation.userId,
                     delegation.signature,
                     signatureKey,
                     encryptionKey,
                     {userEncryptionKey.publicKey, encryptedUserKey},
                     isGhostDevice};

  return DeviceCreation{dc};
}

bool verifyDelegationSignature(
    DeviceCreation const& dc,
    Crypto::PublicSignatureKey const& publicSignatureKey)
{
  auto const& v = dc.variant();

  return mpark::visit(
      [&](auto const& d) {
        std::array<std::uint8_t,
                   Crypto::PublicSignatureKey::arraySize + UserId::arraySize>
            toVerify;

        auto it = std::copy(d.ephemeralPublicSignatureKey.begin(),
                            d.ephemeralPublicSignatureKey.end(),
                            toVerify.begin());

        std::copy(d.userId.begin(), d.userId.end(), it);
        return Crypto::verify(
            toVerify, d.delegationSignature, publicSignatureKey);
      },
      v);
}

bool operator==(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs)
{
  return std::tie(lhs.ephemeralPublicSignatureKey,
                  lhs.userId,
                  lhs.delegationSignature,
                  lhs.publicSignatureKey,
                  lhs.publicEncryptionKey) ==
         std::tie(rhs.ephemeralPublicSignatureKey,
                  rhs.userId,
                  rhs.delegationSignature,
                  rhs.publicSignatureKey,
                  rhs.publicEncryptionKey);
}

bool operator!=(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs)
{
  return !(lhs == rhs);
}

bool operator==(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs)
{
  return std::tie(lhs.ephemeralPublicSignatureKey,
                  lhs.userId,
                  lhs.delegationSignature,
                  lhs.publicSignatureKey,
                  lhs.publicEncryptionKey,
                  lhs.userKeyPair,
                  lhs.isGhostDevice) ==
         std::tie(rhs.ephemeralPublicSignatureKey,
                  rhs.userId,
                  rhs.delegationSignature,
                  rhs.publicSignatureKey,
                  rhs.publicEncryptionKey,
                  rhs.userKeyPair,
                  rhs.isGhostDevice);
}

bool operator!=(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs)
{
  return !(lhs == rhs);
}

bool operator==(DeviceCreation const& lhs, DeviceCreation const& rhs)
{
  return lhs.variant() == rhs.variant();
}

bool operator!=(DeviceCreation const& lhs, DeviceCreation const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceCreation1& dc)
{
  deserializeDeviceCreationCommonFields(ss, dc);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceCreation3& dc)
{
  deserializeDeviceCreationCommonFields(ss, dc);
  Serialization::deserialize(ss, dc.userKeyPair);
  dc.isGhostDevice = static_cast<bool>(ss.read(1)[0]);
}

std::size_t serialized_size(DeviceCreation const& dc)
{
  return Serialization::serialized_size(dc.variant());
}

void to_json(nlohmann::json& j, DeviceCreation1 const& dc)
{
  jsonifyDeviceCreationCommonFields(j, dc);
}

void to_json(nlohmann::json& j, DeviceCreation3 const& dc)
{
  jsonifyDeviceCreationCommonFields(j, dc);
  j["userKeyPair"] = dc.userKeyPair;
  j["is_ghost_device"] = dc.isGhostDevice;
}

void to_json(nlohmann::json& j, DeviceCreation const& dc)
{
  mpark::visit([&](auto const& a) { j = a; }, dc.variant());
}
}
