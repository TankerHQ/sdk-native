#pragma once

#include <boost/container/map.hpp>

#include <optional>
#include <string>
#include <utility>

// Courtesy include: You probably want this (and it's not a big file)
#include <Tanker/Network/HttpHeader.hpp>

namespace Tanker::Network
{
class HttpHeaderMap
{
public:
  // A header value is not *necessarily* UTF-8, but hold it as a string for convenience
  using HeaderValue = std::string;
  using HeaderName = std::string;

private:
  using ValueType = std::pair<HeaderName const, HeaderValue>;
  using InnerMap = boost::container::multimap<HeaderName, HeaderValue>;

public:
  HttpHeaderMap() = default;
  HttpHeaderMap(std::initializer_list<ValueType> list);
  HttpHeaderMap& operator=(std::initializer_list<ValueType> list);

  // Returns a reference to the header value, if present
  // If there are multiple values with this key, the first is returned
  // Use find_all if you need all values of a header
  [[nodiscard]] std::optional<HeaderValue const> get(HeaderName const& k) const;

  // Returns an iterator over all values of a header
  [[nodiscard]] InnerMap::const_iterator find_all(HeaderName const& k) const;

  // Adds a header, replacing any previous value with the same name.
  void set(HeaderName const& k, HeaderValue const& v);
  void set(HeaderName&& k, HeaderValue&& v);
  void set(ValueType const& pair);
  void set(ValueType&& pair);

  // Adds a header, appending its value to any previous with the same name.
  // This allows a HTTP header to have multiple values.
  void append(HeaderName const& k, HeaderValue const& v);
  void append(HeaderName&& k, HeaderValue&& v);
  void append(ValueType const& pair);
  void append(ValueType&& pair);

  // Remove a header (and all its values)
  void erase(HeaderName const& k);

  InnerMap::const_iterator begin() const noexcept;
  InnerMap::const_iterator end() const noexcept;

private:
  InnerMap headers;
};
}
