#include <Generator/Generator.hpp>
#include <Tanker/ConnectionFactory.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Unlock/Messages.hpp>

#include <Generator/Utils.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <cppcodec/base64_default_rfc4648.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

TLOG_CATEGORY(Generator);

namespace Tanker
{
namespace Generator
{
using namespace literals;

Gen::Gen(std::string url, std::string idToken, std::size_t nb_cl)
  : _uuidGen(),
    _admin(std::make_unique<Admin>(
        ConnectionFactory::create(url, nonstd::nullopt), idToken)),
    _keyPair{Crypto::makeSignatureKeyPair()},
    _trustchainId{},
    _name{defaultName()},
    _currentClient{0}

{
  // FIXME
  for (auto i = 0u; i < nb_cl; ++i)
    _clients.emplace_back(std::make_unique<Client>(ConnectionFactory::create(
        url, SdkInfo{"test", _trustchainId, "0.0.1"})));
}

std::string Gen::createUid() const noexcept
{
  return to_string(this->_uuidGen());
}

std::string Gen::defaultName()
{
  return fmt::format("functest-cpp-{}", to_string(UuIdGen()()));
}

std::string to_string(Gen const& tc)
{
  return nlohmann::json(tc).dump(2);
}

void to_json(nlohmann::json& j, Gen const& tc)
{
  j = nlohmann::json{{"id", tc.trustchainId()},
                     {"name", tc.name()},
                     {"private_key", tc._keyPair.privateKey},
                     {"public_key", tc._keyPair.publicKey}};
}

Gen::~Gen()
{
  if (!this->_keep && !this->name().empty())
  {
    tc::async_resumable([this]() -> tc::cotask<void> {
      TC_AWAIT(_admin->deleteTrustchain(this->_trustchainId));
    })
        .get();
  }
}

Gen& Gen::create(bool keep) &
{
  tc::async_resumable([&, this]() -> tc::cotask<void> {
    TC_AWAIT(_admin->start());
    for (auto&& client : _clients)
      client->start();
    _keep = keep;
    _trustchainId =
        TC_AWAIT(_admin->createTrustchain(this->_name, this->_keyPair, !keep));
  })
      .get();
  return *this;
}

Gen& Gen::use(std::string trustchainId, std::string privateKey) &
{
  this->_trustchainId = base64::decode<Crypto::Hash>(trustchainId);
  this->_keep = true;
  this->_name = "";
  this->_keyPair = Crypto::makeSignatureKeyPair(
      base64::decode<Crypto::PrivateSignatureKey>(privateKey));
  this->_keep = true;
  tc::async_resumable([&, this]() -> tc::cotask<void> {
    TC_AWAIT(_admin->start());
    for (auto&& client : _clients)
      client->start();
  })
      .get();
  return *this;
}

Gen&& Gen::create(bool keep) &&
{
  tc::async_resumable([&, this]() -> tc::cotask<void> {
    TC_AWAIT(_admin->start());
    for (auto&& client : _clients)
      client->start();
    _keep = keep;
    _trustchainId =
        TC_AWAIT(_admin->createTrustchain(this->_name, this->_keyPair, !keep));
  })
      .get();
  return std::move(*this);
}

Gen&& Gen::use(std::string trustchainId, std::string privateKey) &&
{
  this->_trustchainId = base64::decode<Crypto::Hash>(trustchainId);
  this->_keep = true;
  this->_name = "";
  this->_keyPair = Crypto::makeSignatureKeyPair(
      base64::decode<Crypto::PrivateSignatureKey>(privateKey));
  tc::async_resumable([&, this]() -> tc::cotask<void> {
    TC_AWAIT(_admin->start());
    for (auto&& client : _clients)
      client->start();
  })
      .get();
  return std::move(*this);
}

Devices Gen::make(UserQuant q)
{
  Devices users;
  users.reserve(q.value);
  for (auto c = 0u; c < q.value; c++)
    users.emplace_back(
        SUserId{this->createUid()}, this->_trustchainId, keyPair().privateKey);
  return users;
}

Device Gen::makeUser() noexcept
{
  return std::move(make(1_users).front());
}

Shares Gen::makeShares(Device const& sender,
                       Devices::const_iterator beg,
                       Devices::const_iterator end,
                       Resource res)
{
  Shares shares;
  auto const count = std::distance(beg, end) - 1;
  shares.reserve(count);
  std::generate_n(std::back_inserter(shares), count, [&] {
    // FIXME or the server...
    if (beg->deviceId == sender.deviceId)
      std::advance(beg, 1);
    return Share(sender, *beg++, res);
  });

  return shares;
}

Shares Gen::make(ShareQuant q, Devices const& recipients)
{
  Shares shares;
  shares.reserve(q.value * recipients.size());
  auto userIt = begin(recipients);
  for (auto i = 0u; i < q.value; ++i)
  {
    auto datShares =
        this->makeShares(*userIt, begin(recipients), end(recipients));
    std::move(begin(datShares), end(datShares), std::back_inserter(shares));
    if (++userIt == end(recipients))
      userIt = begin(recipients);
  }
  return shares;
}

Devices Gen::make(UnlockPassword password, Devices const& users)
{
  Devices devices;
  devices.reserve(users.size());
  std::transform(begin(users),
                 end(users),
                 std::back_inserter(devices),
                 [&](auto const& user) { return user.make(password); });
  return devices;
}

void Gen::upload(UnlockPassword const& password, Devices const& ghosts)
{
  std::vector<tc::future<void>> futs;
  futs.reserve(ghosts.size());
  for (auto const& ghost : ghosts)
  {
    auto const msg =
        Unlock::Message(base64::decode<TrustchainId>(trustchainId()),
                        ghost.deviceId,
                        Unlock::UpdateOptions{}
                            .set(Password{password})
                            .set(ghost.asUnlockKey()),
                        Crypto::makeSymmetricKey(),
                        ghost.sigKeys.privateKey);
    auto fut = this->dispatch(
        [message = std::move(msg)](auto&& client) -> tc::cotask<void> {
          TC_AWAIT(client->createUnlockKey(message));
        });
    futs.push_back(std::move(fut));
  }
  tc::when_all(std::make_move_iterator(begin(futs)),
               std::make_move_iterator(end(futs)))
      .get();
}

void Gen::pushKeys(gsl::span<Share const> keys)
{
  auto point = std::begin(keys);
  auto ending = std::end(keys);
  std::vector<tc::future<void>> futs;
  while (point != ending)
  {
    auto old_point = point;
    point = std::find_if(point, ending, [sender = point->sender](auto&& key) {
      return (key.sender != sender);
    });
    auto fut = this->dispatch([&](auto&& client) -> tc::cotask<void> {
      std::vector<std::vector<uint8_t>> sb;
      sb.reserve(std::distance(old_point, point));
      transform(old_point, point, back_inserter(sb), [](auto&& k) {
        return k.buffer;
      });
      TC_AWAIT(client->pushKeys(sb));
    });
    futs.push_back(std::move(fut));
  }
  tc::when_all(std::make_move_iterator(begin(futs)),
               std::make_move_iterator(end(futs)))
      .get();
}

Crypto::SignatureKeyPair const& Gen::keyPair() const noexcept
{
  return this->_keyPair;
}

std::string const& Gen::name() const noexcept
{
  return this->_name;
}

std::string Gen::trustchainId() const
{
  return base64::encode(this->_trustchainId);
}
}
} /* Tanker */
