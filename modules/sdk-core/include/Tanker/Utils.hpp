#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <algorithm>
#include <type_traits>
#include <vector>

namespace Tanker
{
template <typename T, typename String>
T base64DecodeArgument(String const& b64)
{
  using namespace Tanker::Errors;

  try
  {
    return cppcodec::base64_rfc4648::decode<T>(b64);
  }
  catch (cppcodec::parse_error const&)
  {
    throw Exception(make_error_code(Errc::InvalidArgument),
                    "base64 deserialization failed");
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
    return base64DecodeArgument<Trustchain::GroupId>(sgroupId.string());
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
