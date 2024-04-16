#include <Tanker/Network/HttpHeaderMap.hpp>

#include <boost/algorithm/string.hpp>

using boost::algorithm::to_lower_copy;

namespace Tanker::Network
{
HttpHeaderMap::HttpHeaderMap(std::initializer_list<ValueType> list)
{
  for (auto const& elem : list)
    append(elem);
}

HttpHeaderMap& HttpHeaderMap::operator=(std::initializer_list<ValueType> list)
{
  headers = {};
  for (auto const& elem : list)
    append(elem);
  return *this;
}

std::optional<HttpHeaderMap::HeaderValue const> HttpHeaderMap::get(const HeaderName& k) const
{
  auto it = headers.find(to_lower_copy(k));
  if (it == headers.end())
    return std::nullopt;
  else
    return it->second;
}

HttpHeaderMap::InnerMap::const_iterator HttpHeaderMap::find_all(const HeaderName& k) const
{
  return headers.find(to_lower_copy(k));
}

void HttpHeaderMap::set(HeaderName const& k, HeaderValue const& v)
{
  auto lower_key = to_lower_copy(k);
  headers.erase(lower_key);
  headers.insert({lower_key, v});
}

void HttpHeaderMap::set(ValueType const& pair)
{
  set(pair.first, pair.second);
}

void HttpHeaderMap::append(HeaderName const& k, HeaderValue const& v)
{
  headers.insert({to_lower_copy(k), v});
}

void HttpHeaderMap::append(ValueType const& pair)
{
  append(pair.first, pair.second);
}

void HttpHeaderMap::erase(HeaderName const& k)
{
  headers.erase(to_lower_copy(k));
}

HttpHeaderMap::InnerMap::const_iterator HttpHeaderMap::begin() const noexcept
{
  return headers.begin();
}

HttpHeaderMap::InnerMap::const_iterator HttpHeaderMap::end() const noexcept
{
  return headers.end();
}
}
