#pragma once

#include <cstdint>
#include <tuple>
#include <utility>

#define TANKER_CRYPTO_ARRAY_HELPERS(Self)                            \
  template <size_t I>                                                \
  constexpr uint8_t& get(Self& s) noexcept                           \
  {                                                                  \
    return get<I>(s.base());                                         \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t&& get(Self&& s) noexcept                         \
  {                                                                  \
    return get<I>(std::move(s).base());                              \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t const& get(Self const& s) noexcept               \
  {                                                                  \
    return get<I>(s.base());                                         \
  }                                                                  \
                                                                     \
  template <size_t I>                                                \
  constexpr uint8_t const&& get(Self const&& s) noexcept             \
  {                                                                  \
    return get<I>(std::move(s).base());                              \
  }                                                                  \
                                                                     \
  inline void swap(Self& lhs, Self& rhs)                             \
  {                                                                  \
    lhs.swap(rhs.base());                                            \
  }                                                                  \
                                                                     \
  template <>                                                        \
  class tuple_size<Self> : public tuple_size<typename Self::array_t> \
  {                                                                  \
  };                                                                 \
                                                                     \
  template <size_t I>                                                \
  class tuple_element<I, Self>                                       \
    : public tuple_element<I, typename Self::array_t>                \
  {                                                                  \
  }

#define TANKER_CRYPTO_ARRAY_HELPERS_NON_TYPE_TPL_ARGS(Self, Arg1, Arg2) \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                   \
  constexpr uint8_t& get(Self<KT, KU, Tag>& s) noexcept                 \
  {                                                                     \
    return get<I>(s.base());                                            \
  }                                                                     \
                                                                        \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                   \
  constexpr uint8_t&& get(Self<KT, KU, Tag>&& s) noexcept               \
  {                                                                     \
    return get<I>(std::move(s).base());                                 \
  }                                                                     \
                                                                        \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                   \
  constexpr uint8_t const& get(Self<KT, KU, Tag> const& s) noexcept     \
  {                                                                     \
    return get<I>(s.base());                                            \
  }                                                                     \
                                                                        \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                   \
  constexpr uint8_t const&& get(Self<KT, KU, Tag> const&& s) noexcept   \
  {                                                                     \
    return get<I>(std::move(s).base());                                 \
  }                                                                     \
                                                                        \
  template <Arg1 KT, Arg2 KU, typename Tag>                             \
  void swap(Self<KT, KU, Tag>& lhs, Self<KT, KU, Tag>& rhs)             \
  {                                                                     \
    lhs.swap(rhs.base());                                               \
  }                                                                     \
                                                                        \
  template <Arg1 KT, Arg2 KU, typename Tag>                             \
  class tuple_size<Self<KT, KU, Tag>>                                   \
    : public tuple_size<typename Self<KT, KU, Tag>::array_t>            \
  {                                                                     \
  };                                                                    \
                                                                        \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>                   \
  class tuple_element<I, Self<KT, KU, Tag>>                             \
    : public tuple_element<I, typename Self<KT, KU, Tag>::array_t>      \
  {                                                                     \
  }

#define TANKER_CRYPTO_ARRAY_HELPERS_TPL_ARG(Self)                          \
  template <size_t I, typename T>                                          \
  constexpr uint8_t& get(Self<T>& s) noexcept                              \
  {                                                                        \
    return get<I>(s.base());                                               \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t&& get(Self<T>&& s) noexcept                            \
  {                                                                        \
    return get<I>(std::move(s).base());                                    \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t const& get(Self<T> const& s) noexcept                  \
  {                                                                        \
    return get<I>(s.base());                                               \
  }                                                                        \
                                                                           \
  template <size_t I, typename T>                                          \
  constexpr uint8_t const&& get(Self<T> const&& s) noexcept                \
  {                                                                        \
    return get<I>(std::move(s).base());                                    \
  }                                                                        \
                                                                           \
  template <typename T>                                                    \
  void swap(Self<T>& lhs, Self<T>& rhs)                                    \
  {                                                                        \
    lhs.swap(rhs.base());                                                  \
  }                                                                        \
                                                                           \
  template <typename T>                                                    \
  class tuple_size<Self<T>> : public tuple_size<typename Self<T>::array_t> \
  {                                                                        \
  };                                                                       \
                                                                           \
  template <size_t I, typename T>                                          \
  class tuple_element<I, Self<T>>                                          \
    : public tuple_element<I, typename Self<T>::array_t>                   \
  {                                                                        \
  }
