#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

Tanker::Entry toVerifiedEntry(
    Tanker::Trustchain::ServerEntry const& serverEntry);
