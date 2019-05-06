#pragma once

#include <Tanker/Trustchain/Preprocessor/detail/Common.hpp>

#include <boost/preprocessor/arithmetic/add.hpp>
#include <boost/preprocessor/comparison/less.hpp>
#include <boost/preprocessor/empty.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/for_each_i.hpp>
#include <boost/preprocessor/seq/size.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>

#include <tuple>

#define TANKER_DETAIL_DESERIALIZE(unused1, unused2, elem) \
  Serialization::deserialize_to(ss, k.TANKER_DETAIL_ATTRIBUTE_NAME(elem));

#define TANKER_DETAIL_DEFINE_ACTION_DESERIALIZATION(name, list)              \
  void from_serialized(Serialization::SerializedSource& ss, name& k)         \
  {                                                                          \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_DESERIALIZE, BOOST_PP_EMPTY(), list) \
  }

#define TANKER_DETAIL_SERIALIZE(unused1, unused2, elem) \
  it = Serialization::serialize(it, k.TANKER_DETAIL_PARAMETER_NAME(elem)());

#define TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION(name, list)              \
  std::uint8_t* to_serialized(std::uint8_t* it, name const& k)             \
  {                                                                        \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_SERIALIZE, BOOST_PP_EMPTY(), list) \
    return it;                                                             \
  }

#define TANKER_DETAIL_SERIALIZED_SIZE(unused1, size, idx, elem) \
  BOOST_PP_IF(idx, +, BOOST_PP_EMPTY())                         \
  Serialization::serialized_size(k.TANKER_DETAIL_PARAMETER_NAME(elem)())

#define TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION_SIZE(name, list) \
  std::size_t serialized_size(name const& k)                       \
  {                                                                \
    return BOOST_PP_SEQ_FOR_EACH_I(                                \
        TANKER_DETAIL_SERIALIZED_SIZE, BOOST_PP_EMPTY(), list);    \
  }

#define TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(name, ...) \
  TANKER_DETAIL_DEFINE_ACTION_DESERIALIZATION(                   \
      name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))               \
  TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION(                     \
      name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))               \
  TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION_SIZE(                \
      name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(name)          \
  void from_serialized(Serialization::SerializedSource& ss, name& k); \
  std::uint8_t* to_serialized(std::uint8_t* it, name const& k);       \
  std::size_t serialized_size(name const& k);                         \
  \
