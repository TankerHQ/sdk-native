#include <Tanker/DataStore/Utils.hpp>

#include <Tanker/Crypto/Errors/ErrcCategory.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Errors/ErrcCategory.hpp>

TLOG_CATEGORY(DataStore);

namespace Tanker::DataStore
{
[[noreturn]] void handleError(Errors::Exception const& e)
{
  if (e.errorCode().category() == Serialization::ErrcCategory() ||
      e.errorCode().category() == Crypto::ErrcCategory() ||
      e.errorCode() == Errors::Errc::InvalidArgument)
  {
    TERROR("Failed to decrypt/deserialize database buffer: {}", e.what());
    throw Errors::Exception(
        DataStore::Errc::DatabaseCorrupt,
        "database is corrupted, or an incorrect identity was used");
  }
  else
    throw;
}
}
