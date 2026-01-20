#pragma once

#include <string_view>

#include "gdbstub/protocol/rsp_core.hpp"
#include "gdbstub/protocol/rsp_types.hpp"
#include "gdbstub/server/server.hpp"
#include "gdbstub/target/target.hpp"
#include "gdbstub/transport/transport.hpp"
#include "gdbstub/transport/transport_tcp.hpp"

namespace gdbstub {

std::string_view version();

} // namespace gdbstub
