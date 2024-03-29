#include <Tanker/Groups/Requester.hpp>

#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Utils.hpp>

#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>
#include <range/v3/functional/compose.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker::Groups
{
Requester::Requester(Network::HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocksImpl(nlohmann::json const& query)
{
  auto url = _httpClient->makeUrl("user-group-histories", query);
  auto const response = TC_AWAIT(_httpClient->asyncGet(url)).value();
  auto const histories = response.at("histories").get<std::vector<std::string>>();
  TC_RETURN(histories |
            ranges::views::transform(ranges::compose(Trustchain::deserializeGroupAction, mgs::base64::lazy_decode())) |
            ranges::to<std::vector>);
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    gsl::span<Trustchain::GroupId const> groupIds)
{
  if (groupIds.empty())
    TC_RETURN(std::vector<Trustchain::GroupAction>{});
  auto const query =
      nlohmann::json{{"user_group_ids[]", groupIds | ranges::views::transform(mgs::base64url_nopad::lazy_encode())}};
  TC_RETURN(TC_AWAIT(getGroupBlocksImpl(query)));
}

tc::cotask<std::vector<Trustchain::GroupAction>> Requester::getGroupBlocks(
    Crypto::PublicEncryptionKey const& groupEncryptionKey)
{
  auto const query = nlohmann::json{
      {"user_group_public_encryption_key", mgs::base64url_nopad::encode(groupEncryptionKey)}};
  TC_RETURN(TC_AWAIT(getGroupBlocksImpl(query)));
}

tc::cotask<void> Requester::createGroup(Trustchain::Actions::UserGroupCreation const& groupCreation)
{
  TC_AWAIT(
      _httpClient->asyncPost(_httpClient->makeUrl("user-groups"),
                             {{"user_group_creation", mgs::base64::encode(Serialization::serialize(groupCreation))}}))
      .value();
}

tc::cotask<void> Requester::updateGroup(Trustchain::Actions::UserGroupAddition const& groupAddition)
{
  TC_AWAIT(
      _httpClient->asyncPatch(_httpClient->makeUrl("user-groups"),
                              {{"user_group_addition", mgs::base64::encode(Serialization::serialize(groupAddition))}}))
      .value();
}

tc::cotask<void> Requester::softUpdateGroup(Trustchain::Actions::UserGroupRemoval const& groupRemoval,
                                            std::optional<Trustchain::Actions::UserGroupAddition> const& groupAddition)
{
  nlohmann::json body{{"user_group_removal", mgs::base64::encode(Serialization::serialize(groupRemoval))}};
  if (groupAddition)
    body["user_group_addition"] = mgs::base64::encode(Serialization::serialize(*groupAddition));
  TC_AWAIT(_httpClient->asyncPost(_httpClient->makeUrl("user-groups/soft-update"), body)).value();
}
}
