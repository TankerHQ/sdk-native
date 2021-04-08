#include <Tanker/Groups/Requester.hpp>

#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Utils.hpp>

#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
namespace
{
std::vector<Trustchain::GroupAction> fromBlocksToGroupActions(
    gsl::span<std::string const> blocks)
{
  std::vector<Trustchain::GroupAction> entries;
  entries.reserve(blocks.size());
  std::transform(
      std::begin(blocks),
      std::end(blocks),
      std::back_inserter(entries),
      [](auto const& block) {
        return Trustchain::deserializeGroupAction(mgs::base64::decode(block));
      });

  return entries;
}
}

Requester::Requester(HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocksImpl(
    nlohmann::json const& query)
{
  auto url = _httpClient->makeUrl("user-group-histories");
  url.set_search(fetchpp::http::encode_query(query));
  auto const response = TC_AWAIT(_httpClient->asyncGet(url.href())).value();
  TC_RETURN(fromBlocksToGroupActions(
      response.at("histories").get<std::vector<std::string>>()));
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    gsl::span<Trustchain::GroupId const> groupIds)
{
  if (groupIds.empty())
    TC_RETURN(std::vector<Trustchain::GroupAction>{});
  auto const query = nlohmann::json{
      {"user_group_ids[]", encodeCryptoTypes<mgs::base64url_nopad>(groupIds)},
      {"is_light", "true"}};
  TC_RETURN(TC_AWAIT(getGroupBlocksImpl(query)));
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    Crypto::PublicEncryptionKey const& groupEncryptionKey)
{
  auto const query =
      nlohmann::json{{"user_group_public_encryption_key",
                      mgs::base64url_nopad::encode(groupEncryptionKey)},
                     {"is_light", "true"}};
  TC_RETURN(TC_AWAIT(getGroupBlocksImpl(query)));
}

tc::cotask<void> Requester::createGroup(
    Trustchain::Actions::UserGroupCreation const& groupCreation)
{
  auto const url = _httpClient->makeUrl("user-groups");
  TC_AWAIT(
      _httpClient->asyncPost(
          url.href(),
          {{"user_group_creation",
            mgs::base64::encode(Serialization::serialize(groupCreation))}}))
      .value();
}

tc::cotask<void> Requester::updateGroup(
    Trustchain::Actions::UserGroupAddition const& groupAddition)
{
  auto const url = _httpClient->makeUrl("user-groups");
  TC_AWAIT(
      _httpClient->asyncPatch(
          url.href(),
          {{"user_group_addition",
            mgs::base64::encode(Serialization::serialize(groupAddition))}}))
      .value();
}
}
}
