#pragma once

#include <Tanker/Trustchain/Preprocessor/detail/Common.hpp>

#include <Tanker/Serialization/SerializedSource.hpp>

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

#define TANKER_DETAIL_DEFINE_DATA_DESERIALIZATION(name, list)                \
  void from_serialized(Serialization::SerializedSource& ss, name& k)         \
  {                                                                          \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_DESERIALIZE, BOOST_PP_EMPTY(), list) \
  }

#define TANKER_DETAIL_SERIALIZE(unused1, unused2, elem) \
  it = Serialization::serialize(it, k.TANKER_DETAIL_PARAMETER_NAME(elem)());

#define TANKER_DETAIL_DEFINE_DATA_SERIALIZATION(name, list)                \
  std::uint8_t* to_serialized(std::uint8_t* it, name const& k)             \
  {                                                                        \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_SERIALIZE, BOOST_PP_EMPTY(), list) \
    return it;                                                             \
  }

#define TANKER_DETAIL_SERIALIZED_SIZE(unused1, size, idx, elem) \
  BOOST_PP_IF(idx, +, BOOST_PP_EMPTY())                         \
  Serialization::serialized_size(k.TANKER_DETAIL_PARAMETER_NAME(elem)())

#define TANKER_DETAIL_DEFINE_DATA_SERIALIZATION_SIZE(name, list)                           \
  std::size_t serialized_size(name const& k)                                               \
  {                                                                                        \
    return BOOST_PP_SEQ_FOR_EACH_I(TANKER_DETAIL_SERIALIZED_SIZE, BOOST_PP_EMPTY(), list); \
  }

#define TANKER_TRUSTCHAIN_DATA_DEFINE_SERIALIZATION(name, ...)                           \
  TANKER_DETAIL_DEFINE_DATA_DESERIALIZATION(name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__)) \
  TANKER_DETAIL_DEFINE_DATA_SERIALIZATION(name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))   \
  TANKER_DETAIL_DEFINE_DATA_SERIALIZATION_SIZE(name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define TANKER_DETAIL_DEFINE_PAYLOAD_SIZE(name, list)                                      \
  namespace                                                                                \
  {                                                                                        \
  unsigned int payload_size(name const& k)                                                 \
  {                                                                                        \
    return BOOST_PP_SEQ_FOR_EACH_I(TANKER_DETAIL_SERIALIZED_SIZE, BOOST_PP_EMPTY(), list); \
  }                                                                                        \
  }

#define TANKER_DETAIL_DEFINE_ACTION_DESERIALIZATION(name, list)              \
  void from_serialized(Serialization::SerializedSource& ss, name& k)         \
  {                                                                          \
    deserializeBlockVersion(ss);                                             \
    ss.read_varint(); /* index is ignored */                                 \
    Serialization::deserialize_to(ss, k._trustchainId);                      \
    deserializeBlockNature(ss, name::nature());                              \
    ss.read_varint(); /* payload size is ignored */                          \
                                                                             \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_DESERIALIZE, BOOST_PP_EMPTY(), list) \
                                                                             \
    k._hash = k.computeHash();                                               \
  }

#define TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION(name, list)              \
  std::uint8_t* to_serialized(std::uint8_t* it, name const& k)             \
  {                                                                        \
    it = Serialization::varint_write(it, 1); /* block version */           \
    it = Serialization::varint_write(it, 0); /* block index */             \
    it = Serialization::serialize(it, k.trustchainId());                   \
    it = Serialization::varint_write(it, static_cast<int>(k.nature()));    \
    it = Serialization::varint_write(it, payload_size(k));                 \
                                                                           \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_SERIALIZE, BOOST_PP_EMPTY(), list) \
    return it;                                                             \
  }

#define TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION_SIZE(name)                                              \
  std::size_t serialized_size(name const& k)                                                              \
  {                                                                                                       \
    auto const payloadSize = payload_size(k);                                                             \
    return 1 + /* version */                                                                              \
           1 + /* index */                                                                                \
           TrustchainId::arraySize + Serialization::varint_size(static_cast<int>(name::nature())) +       \
           Serialization::varint_size(payloadSize) + payloadSize + Crypto::Hash::arraySize + /* author */ \
           Crypto::Signature::arraySize;                                                                  \
  }

#define TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(name, ...)                                           \
  TANKER_DETAIL_DEFINE_PAYLOAD_SIZE(name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))                           \
  TANKER_DETAIL_DEFINE_ACTION_DESERIALIZATION(                                                             \
      name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__, (author, Crypto::Hash), (signature, Crypto::Signature))) \
  TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION(                                                               \
      name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__, (author, Crypto::Hash), (signature, Crypto::Signature))) \
  TANKER_DETAIL_DEFINE_ACTION_SERIALIZATION_SIZE(name)

#define TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(name)          \
  void from_serialized(Serialization::SerializedSource& ss, name& k); \
  std::uint8_t* to_serialized(std::uint8_t* it, name const& k);       \
  std::size_t serialized_size(name const& k);
