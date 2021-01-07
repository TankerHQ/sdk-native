#pragma once

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <cstdint>
#include <string>

Tanker::Functional::Trustchain& getTrustchain();
std::string makePublicIdentity(std::string const& sappId, uint32_t n);
