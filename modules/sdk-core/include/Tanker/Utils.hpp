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
}
