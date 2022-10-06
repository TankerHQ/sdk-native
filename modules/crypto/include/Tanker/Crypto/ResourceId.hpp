#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/CompositeResourceId.hpp>
#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <boost/variant2/variant.hpp>

namespace Tanker::Crypto
{
class ResourceId
  : public boost::variant2::variant<SimpleResourceId, CompositeResourceId>
{
public:
  using base_t =
      boost::variant2::variant<SimpleResourceId, CompositeResourceId>;

  ResourceId() = default;
  template <typename InputIterator, typename Sentinel>
  ResourceId(InputIterator begin, Sentinel end);
  ResourceId(SimpleResourceId const& rid) : base_t(SimpleResourceId{rid})
  {
  }
  ResourceId(SimpleResourceId&& rid) : base_t(rid)
  {
  }
  ResourceId(CompositeResourceId const& rid) : base_t(rid)
  {
  }
  ResourceId(CompositeResourceId&& rid) : base_t(rid)
  {
  }

  SimpleResourceId individualResourceId() const
  {
    return boost::variant2::visit(
        overloaded{[&](SimpleResourceId const& e) { return e; },
                   [&](CompositeResourceId const& e) {
                     return e.individualResourceId();
                   }},
        *this);
  }

  auto begin() const
  {
    return boost::variant2::visit([](auto const& e) { return e.begin(); },
                                  *this);
  }

  auto end() const
  {
    return boost::variant2::visit([](auto const& e) { return e.end(); }, *this);
  }

  std::size_t size() const
  {
    return boost::variant2::visit([](auto const& e) { return e.size(); },
                                  *this);
  }
};

// Do not let doctest pickup variant2's operator<<
inline std::ostream& operator<<(std::ostream& os, ResourceId const&) = delete;

template <typename InputIterator, typename Sentinel>
ResourceId::ResourceId(mgs::meta::input_iterator<InputIterator> begin,
                       mgs::meta::sentinel_for<Sentinel, InputIterator> end)
{

  auto is = mgs::codecs::make_iterator_sentinel_source(begin, end);
  CompositeResourceId::array_t data;
  auto const [it, total_read] =
      Crypto::detail::read_at_most(is, data.data(), data.size());
  // Make sure there is no additional data
  if (is.read(data.data(), 1).second != 0)
  {
    throw Errors::formatEx(
        Crypto::Errc::InvalidBufferSize,
        FMT_STRING("invalid size for {:s}: larger than max expected {:d}"),
        typeid(ResourceId).name(),
        CompositeResourceId::arraySize);
  }

  if (total_read == SimpleResourceId::arraySize)
  {
    emplace<SimpleResourceId>(data.begin(),
                              data.begin() + SimpleResourceId::arraySize);
  }
  else if (total_read == CompositeResourceId::arraySize)
  {
    emplace<CompositeResourceId>(data);
  }
  else
  {
    throw Errors::formatEx(
        Crypto::Errc::InvalidBufferSize,
        FMT_STRING("invalid size for {:s}: got {:d}, expected {:d} or {:d}"),
        typeid(ResourceId).name(),
        total_read,
        SimpleResourceId::arraySize,
        CompositeResourceId::arraySize);
  }
}
}
