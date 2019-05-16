#pragma once

#include <Tanker/Test/Functional/User.hpp>
#include <Tanker/Types/SGroupId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional.hpp>

#include <string>
#include <vector>

struct EncryptState
{
  std::string clearData;
  std::vector<uint8_t> encryptedData;
};

void to_json(nlohmann::json& j, EncryptState const& state);
void from_json(nlohmann::json const& j, EncryptState& state);

struct ShareState
{
  Tanker::Test::User alice;
  Tanker::Test::User bob;
  nonstd::optional<Tanker::SGroupId> groupId;
  EncryptState encryptState;
};

void to_json(nlohmann::json& j, ShareState const& state);
void from_json(nlohmann::json const& j, ShareState& state);

struct IdentityShareState
{
  std::string identity;
  EncryptState encryptState;
};

void to_json(nlohmann::json& j, IdentityShareState const& state);
void from_json(nlohmann::json const& j, IdentityShareState& state);
