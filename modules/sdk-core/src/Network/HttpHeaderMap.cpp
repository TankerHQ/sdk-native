#include <Tanker/Network/HttpHeaderMap.hpp>

namespace Tanker::Network
{
HttpHeaderMap::HttpHeaderMap(std::initializer_list<ValueType> list) : headers{list}
{
}

HttpHeaderMap& HttpHeaderMap::operator=(std::initializer_list<ValueType> list)
{
  headers = list;
  return *this;
}

std::optional<HttpHeaderMap::HeaderValue const> HttpHeaderMap::get(const HeaderName& k) const
{
  auto it = headers.find(k);
  if (it == headers.end())
    return std::nullopt;
  else
    return it->second;
}

HttpHeaderMap::InnerMap::const_iterator HttpHeaderMap::find_all(const HeaderName& k) const
{
  return headers.find(k);
}

void HttpHeaderMap::set(HeaderName const& k, HeaderValue const& v)
{
  headers.erase(k);
  headers.insert({k, v});
}

void HttpHeaderMap::set(HeaderName&& k, HeaderValue&& v)
{
  headers.erase(k);
  headers.insert({std::move(k), std::move(v)});
}

void HttpHeaderMap::set(ValueType const& pair)
{
  headers.erase(pair.first);
  headers.insert(pair);
}

void HttpHeaderMap::set(ValueType&& pair)
{
  headers.erase(pair.first);
  headers.insert(std::move(pair));
}

void HttpHeaderMap::append(HeaderName const& k, HeaderValue const& v)
{
  headers.insert({k, v});
}

void HttpHeaderMap::append(HeaderName&& k, HeaderValue&& v)
{
  headers.insert({std::move(k), std::move(v)});
}

void HttpHeaderMap::append(ValueType const& pair)
{
  headers.insert(pair);
}

void HttpHeaderMap::append(ValueType&& pair)
{
  headers.insert(std::move(pair));
}

void HttpHeaderMap::erase(HeaderName const& k)
{
  headers.erase(k);
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
