#pragma once

#include <cstdint>
#include <tuple>
#include <utility>

#define TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT(Self)                   \
  template <>                                                        \
  class tuple_size<Self> : public tuple_size<typename Self::array_t> \
  {                                                                  \
  };                                                                 \
                                                                     \
  template <size_t I>                                                \
  class tuple_element<I, Self>                                       \
    : public tuple_element<I, typename Self::array_t>                \
  {                                                                  \
  };

#define TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT_NON_TYPE_TPL_ARGS(    \
    Self, Arg1, Arg2)                                              \
  template <Arg1 KT, Arg2 KU, typename Tag>                        \
  class tuple_size<Self<KT, KU, Tag>>                              \
    : public tuple_size<typename Self<KT, KU, Tag>::array_t>       \
  {                                                                \
  };                                                               \
                                                                   \
  template <size_t I, Arg1 KT, Arg2 KU, typename Tag>              \
  class tuple_element<I, Self<KT, KU, Tag>>                        \
    : public tuple_element<I, typename Self<KT, KU, Tag>::array_t> \
  {                                                                \
  };

#define TANKER_CRYPTO_STD_TUPLE_SIZE_ELEMENT_TPL_ARG(Self)                 \
  template <typename T>                                                    \
  class tuple_size<Self<T>> : public tuple_size<typename Self<T>::array_t> \
  {                                                                        \
  };                                                                       \
                                                                           \
  template <size_t I, typename T>                                          \
  class tuple_element<I, Self<T>>                                          \
    : public tuple_element<I, typename Self<T>::array_t>                   \
  {                                                                        \
  };
