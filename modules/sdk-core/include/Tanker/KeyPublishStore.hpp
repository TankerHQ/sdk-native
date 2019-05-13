#pragma once

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>

#include <gsl-lite.hpp>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
class KeyPublishStore
{
public:
  KeyPublishStore(DataStore::ADatabase* dbConn);

  KeyPublishStore() = delete;
  KeyPublishStore(KeyPublishStore const&) = delete;
  KeyPublishStore(KeyPublishStore&&) = delete;
  KeyPublishStore& operator=(KeyPublishStore const&) = delete;
  KeyPublishStore& operator=(KeyPublishStore&&) = delete;
  ~KeyPublishStore() = default;

  tc::cotask<void> put(Trustchain::Actions::KeyPublish const&);
  tc::cotask<void> put(gsl::span<Trustchain::Actions::KeyPublish const>);
  tc::cotask<nonstd::optional<Trustchain::Actions::KeyPublish>> find(
      Trustchain::ResourceId const&);

private:
  DataStore::ADatabase* _db;
};
}
