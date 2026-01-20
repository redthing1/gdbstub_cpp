#include "gdbstub/server/server.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

void server::handle_read_memory(std::string_view args) {
  auto comma = args.find(',');
  if (comma == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1), len)) {
    send_error(0x16);
    return;
  }

  len = std::min<uint64_t>(len, k_max_memory_read);
  std::vector<std::byte> buffer(static_cast<size_t>(len));
  auto status = target_.mem.read_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_read_binary_memory(std::string_view args) {
  auto comma = args.find(',');
  if (comma == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1), len)) {
    send_error(0x16);
    return;
  }

  len = std::min<uint64_t>(len, k_max_memory_read);
  std::vector<std::byte> buffer(static_cast<size_t>(len));
  auto status = target_.mem.read_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet(rsp::escape_binary(std::span<const std::byte>(buffer.data(), buffer.size())));
}

void server::handle_write_memory(std::string_view args) {
  auto colon = args.find(':');
  auto comma = args.find(',');
  if (colon == std::string_view::npos || comma == std::string_view::npos || comma > colon) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1, colon - comma - 1), len)) {
    send_error(0x16);
    return;
  }

  auto hex = args.substr(colon + 1);
  if (hex.size() != len * 2) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(static_cast<size_t>(len));
  if (!rsp::decode_hex(hex, buffer)) {
    send_error(0x16);
    return;
  }

  auto status = target_.mem.write_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_write_binary_memory(std::string_view args) {
  auto colon = args.find(':');
  auto comma = args.find(',');
  if (colon == std::string_view::npos || comma == std::string_view::npos || comma > colon) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1, colon - comma - 1), len)) {
    send_error(0x16);
    return;
  }

  std::string data(args.substr(colon + 1));
  auto actual = rsp::unescape_binary(data);
  if (actual != len) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(data.size());
  std::memcpy(buffer.data(), data.data(), data.size());

  auto status = target_.mem.write_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_memory_region_info(std::string_view addr_str) {
  if (!target_.memory_layout) {
    send_packet("");
    return;
  }

  uint64_t addr = 0;
  if (!parse_hex_u64(addr_str, addr)) {
    send_error(0x16);
    return;
  }

  std::optional<memory_region_info> info;
  if (target_.memory_layout->has_region_info()) {
    info = target_.memory_layout->region_info(addr);
  }

  if (!info && target_.memory_layout->has_memory_map()) {
    auto regions = target_.memory_layout->memory_map();
    std::optional<memory_region_info> mapped = region_info_from_map(regions, addr);
    uint64_t next_start = std::numeric_limits<uint64_t>::max();
    for (const auto& region : regions) {
      auto start = region.start;
      if (start > addr && start < next_start) {
        next_start = start;
      }
    }
    if (mapped) {
      info = std::move(mapped);
    } else {
      uint64_t end_exclusive = next_start;
      if (end_exclusive == std::numeric_limits<uint64_t>::max()) {
        end_exclusive = address_space_end(target_, arch_);
      }
      if (end_exclusive <= addr) {
        end_exclusive = std::numeric_limits<uint64_t>::max();
      }
      if (end_exclusive <= addr) {
        send_error(0x0e);
        return;
      }
      info = unmapped_region_info(addr, end_exclusive - addr);
    }
  }

  if (!info) {
    send_error(0x0e);
    return;
  }

  std::string response;
  response.reserve(128);
  response += "start:" + hex_u64(info->start, sizeof(uint64_t) * 2) + ";";
  response += "size:" + hex_u64(info->size, sizeof(uint64_t) * 2) + ";";
  if (info->mapped) {
    auto perms = perms_to_string(info->perms);
    if (perms.empty()) {
      perms = "rwx";
    }
    response += "permissions:" + perms + ";";
    if (info->name && !info->name->empty()) {
      response += "name:" + hex_encode_string(*info->name) + ";";
    }
    if (!info->types.empty()) {
      response += "type:" + join_types(info->types) + ";";
    }
  }
  send_packet(response);
}

} // namespace gdbstub
