#pragma once

#include <Tanker/Trustchain/Preprocessor/detail/Common.hpp>

#include <boost/preprocessor/empty.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/tuple/enum.hpp>
#include <boost/preprocessor/tuple/rem.hpp>
#include <boost/preprocessor/tuple/remove.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>
#include <mpark/variant.hpp>

#include <type_traits>
#include <utility>

#define TANKER_DETAIL_DEFINE_VARIANT_GETTER(unused1, unused2, elem) \
  TANKER_DETAIL_FULL_PARAMETER(elem)() const                        \
  {                                                                 \
    return this->visit([](auto const& val) -> decltype(auto) {      \
      return val.TANKER_DETAIL_PARAMETER_NAME(elem)();              \
    });                                                             \
  }

#define TANKER_DETAIL_DEFINE_ACTION_VARIANT(name, types, list)         \
  using variant_t = mpark::variant<BOOST_PP_TUPLE_ENUM(types)>;        \
  variant_t _variant;                                                  \
                                                                       \
public:                                                                \
  name() = default;                                                    \
                                                                       \
  template <typename Alternative,                                      \
            typename = std::enable_if_t<                               \
                std::is_constructible<variant_t, Alternative>::value>> \
  name(Alternative&& val) : _variant(std::forward<Alternative>(val))   \
  {                                                                    \
  }                                                                    \
                                                                       \
  template <typename T>                                                \
  bool holdsAlternative() const                                        \
  {                                                                    \
    return mpark::holds_alternative<T>(_variant);                      \
  }                                                                    \
                                                                       \
  template <typename T>                                                \
  T const& get() const                                                 \
  {                                                                    \
    return mpark::get<T>(_variant);                                    \
  }                                                                    \
                                                                       \
  template <typename T>                                                \
  T const* get_if() const                                              \
  {                                                                    \
    return mpark::get_if<T>(_variant);                                 \
  }                                                                    \
                                                                       \
  template <typename Callable>                                         \
  decltype(auto) visit(Callable&& c) const                             \
  {                                                                    \
    return mpark::visit(std::forward<Callable>(c), _variant);          \
  }                                                                    \
                                                                       \
  BOOST_PP_SEQ_FOR_EACH(                                               \
      TANKER_DETAIL_DEFINE_VARIANT_GETTER, BOOST_PP_EMPTY(), list)     \
                                                                       \
  friend bool operator==(name const& lhs, name const& rhs)             \
  {                                                                    \
    return lhs._variant == rhs._variant;                               \
  }                                                                    \
                                                                       \
  friend bool operator!=(name const& lhs, name const& rhs)             \
  {                                                                    \
    return !(lhs == rhs);                                              \
  }

#define TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION( \
    name, types_tuple, ...)                              \
  TANKER_DETAIL_DEFINE_ACTION_VARIANT(                   \
      name, types_tuple, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))
