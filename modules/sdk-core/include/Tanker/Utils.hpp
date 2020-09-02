#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <iostream>

#include <mgs/base64.hpp>

#include <algorithm>
#include <type_traits>
#include <vector>

namespace Tanker
{
template <typename T, typename String>
T base64DecodeArgument(String const& b64, std::string const& argName)
{
  using namespace Tanker::Errors;

  try
  {
    return mgs::base64::decode<T>(b64);
  }
  catch (mgs::exceptions::exception const&)
  {
    throw formatEx(
        Errc::InvalidArgument, "{} has an invalid value: {}", argName, b64);
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Crypto::Errc::InvalidBufferSize)
    {
      throw formatEx(
          Errc::InvalidArgument, "{} has an invalid value: {}", argName, b64);
    }
    throw;
  }
}

template <typename T, typename F>
auto convertList(std::vector<T> const& source, F&& f)
{
  std::vector<std::result_of_t<F(T)>> ret;
  ret.reserve(source.size());

  std::transform(begin(source), end(source), std::back_inserter(ret), f);
  return ret;
}

inline std::vector<Trustchain::GroupId> convertToGroupIds(
    std::vector<SGroupId> const& sgroupIds)
{
  return convertList(sgroupIds, [](auto&& sgroupId) {
    return base64DecodeArgument<Trustchain::GroupId>(sgroupId.string(),
                                                     "group id");
  });
}

struct IdentityFunc
{
  template <typename T>
  T&& operator()(T&& t)
  {
    return std::forward<T>(t);
  }
};

template <typename S, typename T, typename I, typename F = IdentityFunc>
auto mapIdsToStrings(std::vector<T> const& errorIds,
                     std::vector<S> const& sIds,
                     std::vector<I> const& ids,
                     F&& mapToT = IdentityFunc{})
{
  std::vector<S> clearIds;
  clearIds.reserve(ids.size());

  for (auto const& errorId : errorIds)
  {
    auto const idsIt = std::find_if(ids.begin(), ids.end(), [&](auto const& e) {
      return mapToT(e) == errorId;
    });

    assert(idsIt != ids.end() && "Wrong id not found");

    clearIds.push_back(sIds[std::distance(ids.begin(), idsIt)]);
  }
  return clearIds;
}

template <typename T>
std::vector<T> removeDuplicates(std::vector<T> stuff)
{
  std::sort(begin(stuff), end(stuff));
  stuff.erase(std::unique(begin(stuff), end(stuff)), end(stuff));
  return stuff;
}
}
