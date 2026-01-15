#pragma once

#include <string_view>

#include "gdbstub/rsp_core.hpp"
#include "gdbstub/rsp_types.hpp"
#include "gdbstub/server.hpp"
#include "gdbstub/target.hpp"
#include "gdbstub/transport.hpp"
#include "gdbstub/transport_tcp.hpp"

namespace gdbstub {

std::string_view version();

} // namespace gdbstub
