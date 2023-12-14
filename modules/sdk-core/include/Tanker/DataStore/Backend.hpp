#pragma once

#include <gsl/gsl-lite.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Tanker::DataStore
{
enum class OnConflict
{
  Fail,
  Ignore,
  Replace,

  Last,
};

class DataStore;

class Backend
{
public:
  virtual ~Backend() = default;

  virtual std::unique_ptr<DataStore> open(std::string const& dataPath, std::string const& cachePath) = 0;
};

class DataStore
{
public:
  using Key = gsl::span<uint8_t const>;
  using Value = gsl::span<uint8_t const>;

  virtual ~DataStore() = default;

  virtual void nuke() = 0;

  virtual void putSerializedDevice(gsl::span<uint8_t const> device) = 0;
  virtual std::optional<std::vector<uint8_t>> findSerializedDevice() = 0;

  virtual void putCacheValues(gsl::span<std::pair<Key, Value> const> keyValues, OnConflict onConflict) = 0;
  virtual std::vector<std::optional<std::vector<uint8_t>>> findCacheValues(gsl::span<Key const> keys) = 0;
};
}
