#pragma once

#include <Tanker/Trustchain/Preprocessor/detail/Common.hpp>

#include <boost/preprocessor/arithmetic/add.hpp>
#include <boost/preprocessor/comparison/less.hpp>
#include <boost/preprocessor/empty.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/for_each_i.hpp>
#include <boost/preprocessor/seq/size.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>

#include <tuple>

#define TANKER_DETAIL_FIELD_TO_JSON(unused1, unused2, elem)   \
  j[BOOST_PP_STRINGIZE(TANKER_DETAIL_PARAMETER_NAME(elem))] = \
      k.TANKER_DETAIL_PARAMETER_NAME(elem)();

#define TANKER_DETAIL_DEFINE_ACTION_TO_JSON(name, list)                        \
  void to_json(nlohmann::json& j, name const& k)                               \
  {                                                                            \
    BOOST_PP_SEQ_FOR_EACH(TANKER_DETAIL_FIELD_TO_JSON, BOOST_PP_EMPTY(), list) \
  }

#define TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(name, ...) \
  TANKER_DETAIL_DEFINE_ACTION_TO_JSON(name,                \
                                      BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(name) \
  void to_json(nlohmann::json& j, name const& k);
