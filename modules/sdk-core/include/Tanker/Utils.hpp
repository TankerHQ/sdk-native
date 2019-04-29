#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>

#include <algorithm>
#include <type_traits>
#include <vector>

namespace Tanker
{
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
    return cppcodec::base64_rfc4648::decode<Trustchain::GroupId>(
        sgroupId.string());
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
auto toClearId(std::vector<T> const& errorIds,
               std::vector<S> const& sIds,
               std::vector<I> const& Ids,
               F&& mapToT = IdentityFunc{})
{
  std::vector<S> clearIds;
  clearIds.reserve(Ids.size());

  for (auto const& wrongId : errorIds)
  {
    auto const badIt = std::find_if(Ids.begin(), Ids.end(), [&](auto const& e) {
      return mapToT(e) == wrongId;
    });

    assert(badIt != Ids.end() && "Wrong id not found");

    clearIds.push_back(sIds[std::distance(Ids.begin(), badIt)]);
  }
  return clearIds;
}
}
