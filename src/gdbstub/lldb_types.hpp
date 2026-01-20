#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gdbstub::lldb {

enum class kv_encoding { raw, hex_string, hex_u64, dec_u64 };

struct process_kv_pair {
  std::string key;
  std::string value;
  uint64_t u64_value = 0;
  kv_encoding encoding = kv_encoding::raw;
};

struct loaded_libraries_request {
  enum class kind { probe, all, addresses, image_list };
  kind kind = kind::all;
  bool report_load_commands = true;
  std::vector<uint64_t> addresses;
  std::optional<uint64_t> image_list_address;
  std::optional<uint64_t> image_count;
};

struct view {
  void* ctx = nullptr;
  std::optional<std::vector<process_kv_pair>> (*process_info_extras_fn)(void* ctx) = nullptr;
  std::optional<std::string> (*loaded_libraries_json_fn)(
      void* ctx, const loaded_libraries_request& request
  ) = nullptr;

  std::optional<std::vector<process_kv_pair>> process_info_extras() const {
    if (!process_info_extras_fn) {
      return std::nullopt;
    }
    return process_info_extras_fn(ctx);
  }

  std::optional<std::string> loaded_libraries_json(const loaded_libraries_request& request) const {
    if (!loaded_libraries_json_fn) {
      return std::nullopt;
    }
    return loaded_libraries_json_fn(ctx, request);
  }
};

} // namespace gdbstub::lldb
