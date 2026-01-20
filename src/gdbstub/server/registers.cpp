#include "gdbstub/server/server.hpp"

#include <algorithm>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

void server::handle_read_all_registers() {
  std::string out;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    size_t size = target_.regs.reg_size(reg);
    if (size == 0) {
      continue;
    }

    std::vector<std::byte> buffer(size);
    auto status = target_.regs.read_reg(reg, buffer);
    if (status != target_status::ok) {
      out.append(size * 2, 'x');
      continue;
    }

    if (arch_.swap_register_endianness) {
      std::reverse(buffer.begin(), buffer.end());
    }
    out += rsp::encode_hex(buffer);
  }

  send_packet(out);
}

void server::handle_write_all_registers(std::string_view args) {
  size_t total_bytes = 0;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    total_bytes += target_.regs.reg_size(reg);
  }

  if (args.size() != total_bytes * 2) {
    send_error(0x16);
    return;
  }

  size_t offset = 0;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    size_t size = target_.regs.reg_size(reg);
    if (size == 0) {
      continue;
    }

    std::vector<std::byte> buffer(size);
    if (!rsp::decode_hex(args.substr(offset, size * 2), buffer)) {
      send_error(0x16);
      return;
    }

    if (arch_.swap_register_endianness) {
      std::reverse(buffer.begin(), buffer.end());
    }

    auto status = target_.regs.write_reg(reg, buffer);
    if (status != target_status::ok) {
      send_status_error(status, false);
      return;
    }

    offset += size * 2;
  }

  send_packet("OK");
}

void server::handle_read_register(std::string_view args) {
  uint64_t regno = 0;
  if (!parse_hex_u64(args, regno)) {
    send_error(0x16);
    return;
  }

  if (regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_error(0x16);
    return;
  }

  size_t size = target_.regs.reg_size(static_cast<int>(regno));
  if (size == 0) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(size);
  auto status = target_.regs.read_reg(static_cast<int>(regno), buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  if (arch_.swap_register_endianness) {
    std::reverse(buffer.begin(), buffer.end());
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_write_register(std::string_view args) {
  auto eq = args.find('=');
  if (eq == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t regno = 0;
  if (!parse_hex_u64(args.substr(0, eq), regno)) {
    send_error(0x16);
    return;
  }

  if (regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_error(0x16);
    return;
  }

  size_t size = target_.regs.reg_size(static_cast<int>(regno));
  auto hex = args.substr(eq + 1);
  if (size == 0 || hex.size() != size * 2) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(size);
  if (!rsp::decode_hex(hex, buffer)) {
    send_error(0x16);
    return;
  }

  if (arch_.swap_register_endianness) {
    std::reverse(buffer.begin(), buffer.end());
  }

  auto status = target_.regs.write_reg(static_cast<int>(regno), buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_register_info(std::string_view args) {
  if (!target_.reg_info) {
    send_packet("E45");
    return;
  }

  uint64_t regno = 0;
  if (args.empty() || !parse_hex_u64(args, regno)) {
    send_error(0x16);
    return;
  }

  if (arch_.reg_count > 0 && regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_packet("E45");
    return;
  }

  auto info = target_.reg_info->get_register_info(static_cast<int>(regno));
  if (!info) {
    send_packet("E45");
    return;
  }

  auto reg_size = target_.regs.reg_size(static_cast<int>(regno));
  int bitsize = info->bitsize > 0 ? info->bitsize : static_cast<int>(reg_size * 8);
  if (bitsize <= 0) {
    send_error(0x16);
    return;
  }

  size_t offset = 0;
  if (info->offset) {
    offset = *info->offset;
  } else {
    for (int idx = 0; idx < static_cast<int>(regno); ++idx) {
      offset += target_.regs.reg_size(idx);
    }
  }

  std::string response;
  response.reserve(128);
  response += "name:";
  response += info->name;
  response += ";";
  if (info->alt_name && !info->alt_name->empty()) {
    response += "alt-name:";
    response += *info->alt_name;
    response += ";";
  }
  response += "bitsize:";
  response += std::to_string(bitsize);
  response += ";";
  response += "offset:";
  response += std::to_string(offset);
  response += ";";
  response += "encoding:";
  response += info->encoding.empty() ? "uint" : info->encoding;
  response += ";";
  response += "format:";
  response += info->format.empty() ? "hex" : info->format;
  response += ";";
  if (info->set && !info->set->empty()) {
    response += "set:";
    response += *info->set;
    response += ";";
  }
  if (info->gcc_regnum) {
    response += "gcc:";
    response += std::to_string(*info->gcc_regnum);
    response += ";";
  }
  if (info->dwarf_regnum) {
    response += "dwarf:";
    response += std::to_string(*info->dwarf_regnum);
    response += ";";
  }
  if (info->generic && !info->generic->empty()) {
    response += "generic:";
    response += *info->generic;
    response += ";";
  }
  if (!info->container_regs.empty()) {
    response += "container-regs:";
    for (size_t i = 0; i < info->container_regs.size(); ++i) {
      if (i > 0) {
        response.push_back(',');
      }
      response += hex_u64(static_cast<uint64_t>(info->container_regs[i]));
    }
    response += ";";
  }
  if (!info->invalidate_regs.empty()) {
    response += "invalidate-regs:";
    for (size_t i = 0; i < info->invalidate_regs.size(); ++i) {
      if (i > 0) {
        response.push_back(',');
      }
      response += hex_u64(static_cast<uint64_t>(info->invalidate_regs[i]));
    }
    response += ";";
  }

  send_packet(response);
}

} // namespace gdbstub
