#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "gdbstub/target/types.hpp"

namespace gdbstub {

struct arch_spec;
struct target_view;

namespace server_detail {

inline constexpr size_t k_max_packet_size = 4096;
inline constexpr size_t k_max_memory_read = 2048;

std::span<const std::byte> as_bytes(std::string_view text);
std::string hex_encode_string(std::string_view value);
bool decode_hex_string(std::string_view value, std::string& out);
std::optional<process_launch_request> parse_vrun_request(std::string_view args);
std::string hex_byte(uint8_t value);
std::string hex_u64(uint64_t value, size_t width = 0);
bool parse_hex_u64(std::string_view text, uint64_t& value);
std::string perms_to_string(mem_perm perms);
uint64_t address_space_end(const target_view& target, const arch_spec& arch);
bool parse_dec_int(std::string_view text, int& value);
bool parse_thread_token(std::string_view text, std::optional<uint64_t>& tid);

enum class vcont_parse_result { none, ok, invalid };

struct vcont_selection {
  char action = 0;
  std::optional<int> signal;
  std::optional<address_range> range;
};

struct breakpoint_suffixes {
  bool has_thread = false;
  bool has_cond_list = false;
  bool has_cmds = false;
  std::optional<uint64_t> thread_id;
  std::vector<bytecode_expr> conditions;
  std::optional<breakpoint_commands> commands;
};

struct breakpoint_parse_result {
  int type = 0;
  uint64_t addr = 0;
  uint64_t kind = 0;
  breakpoint_suffixes suffixes{};
};

vcont_parse_result parse_vcont_actions(std::string_view actions,
                                       uint64_t current_tid,
                                       vcont_selection& out);
bool split_thread_suffix(std::string_view payload, std::string_view& base, std::optional<uint64_t>& tid);
bool parse_bytecode_list(std::string_view input, std::vector<bytecode_expr>& out);
bool parse_breakpoint_commands(std::string_view input, breakpoint_commands& out);
bool parse_breakpoint_suffixes(std::string_view suffix, breakpoint_suffixes& out);
bool parse_breakpoint_packet(std::string_view args, breakpoint_parse_result& out);
std::string escape_json_string(std::string_view value);
std::optional<uint64_t> parse_json_thread_id(std::string_view json);
bool parse_json_bool(std::string_view json, std::string_view key, bool& value);
std::optional<uint64_t> parse_json_u64(std::string_view json, std::string_view key);
bool parse_json_u64_list(std::string_view json, std::string_view key, std::vector<uint64_t>& values);
std::string stop_reason_label(stop_kind kind);
std::string build_memory_map_xml(const std::vector<memory_region>& regions);
std::string escape_xml_attr(std::string_view value);
std::string build_library_list_xml(const std::vector<library_entry>& libraries);
std::string join_types(const std::vector<std::string>& types);
std::string build_thread_list(const std::vector<uint64_t>& threads);
uint8_t error_code_for_status(target_status status);
std::optional<breakpoint_type> parse_breakpoint_type(int value);
void notify_stop_thunk(void* ctx, const stop_reason& reason);

} // namespace server_detail
} // namespace gdbstub
