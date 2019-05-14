#include "States.hpp"

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

void to_json(nlohmann::json& j, EncryptState const& state)
{
  j["clear_data"] = state.clearData;
  j["encrypted_data"] = cppcodec::base64_rfc4648::encode(state.encryptedData);
}

void from_json(nlohmann::json const& j, EncryptState& state)
{
  j.at("clear_data").get_to(state.clearData);
  auto const str = j.at("encrypted_data").get<std::string>();
  state.encryptedData =
      cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(str);
}

void to_json(nlohmann::json& j, ShareState const& state)
{
  j["alice"] = state.alice;
  j["bob"] = state.bob;
  if (state.groupId)
    j["group"] = state.groupId.value();
  j["encrypt_state"] = state.encryptState;
}

void from_json(nlohmann::json const& j, ShareState& state)
{
  j.at("alice").get_to(state.alice);
  j.at("bob").get_to(state.bob);
  auto group = j.find("group");
  if (group != j.end())
    state.groupId = group->get<Tanker::SGroupId>();
  state.encryptState = j.at("encrypt_state").get<EncryptState>();
}
