#pragma once

#include <Tanker/Trustchain/Preprocessor/detail/Common.hpp>

#include <boost/preprocessor/empty.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/for_each_i.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>

#include <tuple>

#define TANKER_DETAIL_CONSTRUCTOR_ARGS(unused1, unused2, idx, elem) \
  BOOST_PP_COMMA_IF(idx)                                            \
  TANKER_DETAIL_FULL_PARAMETER(elem)

#define TANKER_DETAIL_CONSTRUCTOR_INIT_LIST(unused1, unused2, idx, elem) \
  BOOST_PP_COMMA_IF(idx)                                                 \
  TANKER_DETAIL_ATTRIBUTE_NAME(elem)                                     \
  (TANKER_DETAIL_PARAMETER_NAME(elem))

#define TANKER_DETAIL_OPERATOR_EQUAL_LHS(unused1, unused2, idx, elem) \
  BOOST_PP_COMMA_IF(idx)                                              \
  lhs.TANKER_DETAIL_PARAMETER_NAME(elem)()

#define TANKER_DETAIL_OPERATOR_EQUAL_RHS(unused1, unused2, idx, elem) \
  BOOST_PP_COMMA_IF(idx)                                              \
  rhs.TANKER_DETAIL_PARAMETER_NAME(elem)()

#define TANKER_DETAIL_OPERATOR_EQUAL(list)                                 \
  return std::tie(BOOST_PP_SEQ_FOR_EACH_I(                                 \
             TANKER_DETAIL_OPERATOR_EQUAL_LHS, BOOST_PP_EMPTY(), list)) == \
         std::tie(BOOST_PP_SEQ_FOR_EACH_I(                                 \
             TANKER_DETAIL_OPERATOR_EQUAL_RHS, BOOST_PP_EMPTY(), list));

#define TANKER_DETAIL_DEFINE_CONSTRUCTOR(name, list)                   \
  name(BOOST_PP_SEQ_FOR_EACH_I(                                        \
      TANKER_DETAIL_CONSTRUCTOR_ARGS, BOOST_PP_EMPTY(), list))         \
    : BOOST_PP_SEQ_FOR_EACH_I(                                         \
          TANKER_DETAIL_CONSTRUCTOR_INIT_LIST, BOOST_PP_EMPTY(), list) \
  {                                                                    \
  }

#define TANKER_DETAIL_DEFINE_ACTION(name, list)                              \
public:                                                                      \
  name() = default;                                                          \
  TANKER_DETAIL_DEFINE_CONSTRUCTOR(name, list)                               \
  BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_DEFINE_GETTER, BOOST_PP_EMPTY(), list) \
protected:                                                                   \
  BOOST_PP_SEQ_FOR_EACH(                                                     \
      TANKER_DETAIL_DEFINE_ATTRIBUTE, BOOST_PP_EMPTY(), list)                \
                                                                             \
  friend bool operator==(name const& lhs, name const& rhs)                   \
  {                                                                          \
    TANKER_DETAIL_OPERATOR_EQUAL(list)                                       \
  }                                                                          \
                                                                             \
  friend bool operator!=(name const& lhs, name const& rhs)                   \
  {                                                                          \
    return !(lhs == rhs);                                                    \
  }

#define TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(name, ...) \
  TANKER_DETAIL_DEFINE_ACTION(name, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))
