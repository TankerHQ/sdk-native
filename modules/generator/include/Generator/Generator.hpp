#pragma once

#include <Generator/BlockTypes.hpp>
#include <Generator/Device.hpp>
#include <Generator/Resource.hpp>
#include <tconcurrent/future.hpp>

#include <Tanker/Admin.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <boost/uuid/uuid_generators.hpp>

#include <nlohmann/json_fwd.hpp>

#include <iterator>
#include <memory>

namespace Tanker
{
class Client;
namespace Generator
{

using UuIdGen = boost::uuids::random_generator;

class Gen
{
  UuIdGen mutable _uuidGen;
  std::unique_ptr<Admin> _admin;
  std::vector<std::unique_ptr<Client>> _clients;
  Crypto::SignatureKeyPair _keyPair;
  TrustchainId _trustchainId;
  std::string _name;
  bool _keep;
  std::size_t _currentClient;

  Gen(Gen const&) = delete;
  Gen& operator=(Gen const&) = delete;

  std::string createUid() const noexcept;

  static std::string defaultName();

public:
  Gen(std::string url, std::string idToken, std::size_t nb_cl = 1);
  Gen(Gen&&) = default;
  Gen& operator=(Gen&&) = default;
  ~Gen();

  Gen& create(bool keep = false) &;
  Gen& use(std::string trustchainId, std::string privateKey) &;
  Gen&& create(bool keep = false) &&;
  Gen&& use(std::string trustchainId, std::string privateKey) &&;

  friend std::string to_string(Gen const& tc);
  friend void to_json(nlohmann::json& j, Gen const& tc);

  Devices make(UserQuant count);
  Shares make(ShareQuant count, Devices const& recipients);
  Devices make(UnlockPassword password, Devices const& users);
  void upload(UnlockPassword const& password, Devices const& ghosts);
  Device makeUser() noexcept;
  Shares makeShares(Device const& sender,
                    Devices::const_iterator beg,
                    Devices::const_iterator end,
                    Resource res = Resource{});
  template <typename T>
  tc::cotask<void> pushAdmin(T const&);

  void pushKeys(gsl::span<Share const>);

  template <typename Ite>
  void dispatch(Ite begin, Ite end);
  template <typename Func>
  tc::future<void> dispatch(Func&& f);

  template <typename Block>
  void push(Block const& block);

  std::string const& name() const noexcept;
  Crypto::SignatureKeyPair const& keyPair() const noexcept;
  std::string trustchainId() const;
};

template <typename T>
tc::cotask<void> Gen::pushAdmin(T const& obj)
{
  TC_AWAIT(this->_admin->pushBlock(obj.buffer));
}

template <typename Block>
void Gen::push(Block const& bl)
{
  this->dispatch(
          [&](std::unique_ptr<Client> const& client) -> tc::cotask<void> {
            TC_AWAIT(client->pushBlock(bl.buffer));
          })
      .get();
}

template <typename Func>
tc::future<void> Gen::dispatch(Func&& f)
{
  auto& client = this->_clients.at(_currentClient++ % this->_clients.size());
  return tc::async_resumable(
      [ff = std::forward<Func>(f), &client]() -> tc::cotask<void> {
        TC_AWAIT(ff(client));
      });
}

template <typename Ite>
void Gen::dispatch(Ite start, Ite finish)
{
  std::vector<tc::future<void>> futs;
  for (Ite iter = start; iter != finish; ++iter)
  {
    auto fut = this->dispatch(
        [&](std::unique_ptr<Client> const& client) -> tc::cotask<void> {
          TC_AWAIT(client->pushBlock(iter->buffer));
        });
    futs.push_back(std::move(fut));
  }
  tc::when_all(std::make_move_iterator(begin(futs)),
               std::make_move_iterator(end(futs)))
      .get();
}
}
} /* Tanker */
