#include "gdbstub/server/server.hpp"

#include <algorithm>
#include <cctype>

#include "gdbstub/gdbstub.hpp"
#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

namespace {

std::string normalize_path(std::string_view path, bool case_insensitive) {
  std::string out;
  out.reserve(path.size());
  for (char c : path) {
    char ch = (c == '\\') ? '/' : c;
    if (case_insensitive) {
      ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    out.push_back(ch);
  }
  while (!out.empty() && out.back() == '/') {
    out.pop_back();
  }
  return out;
}

std::string_view basename(std::string_view path) {
  auto pos = path.find_last_of('/');
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

} // namespace

void server::handle_query(std::string_view args) {
  if (args.rfind("Xfer:", 0) == 0) {
    handle_xfer(args.substr(5));
    return;
  }

  auto colon_pos = args.find(':');
  auto name = colon_pos == std::string_view::npos ? args : args.substr(0, colon_pos);
  auto params = colon_pos == std::string_view::npos ? std::string_view{} : args.substr(colon_pos + 1);

  if (name == "Supported") {
    auto caps = run_caps();
    auto bp_caps = breakpoint_caps();

    std::string features;
    features += "PacketSize=";
    features += hex_u64(k_max_packet_size);
    features += ";vContSupported+;QStartNoAckMode+";

    if (!arch_.target_xml.empty() && !arch_.xml_arch_name.empty()) {
      features += ";qXfer:features:read+;xmlRegisters=";
      features += arch_.xml_arch_name;
    }
    if (bp_caps.software) {
      features += ";swbreak+";
    }
    if (bp_caps.hardware) {
      features += ";hwbreak+";
    }
    if (bp_caps.supports_conditional) {
      features += ";ConditionalBreakpoints+";
    }
    if (bp_caps.supports_commands) {
      features += ";BreakpointCommands+";
    }
    if (caps.reverse_continue) {
      features += ";ReverseContinue+";
    }
    if (caps.reverse_step) {
      features += ";ReverseStep+";
    }
    if (caps.non_stop) {
      features += ";QNonStop+";
    }
    if (target_.host) {
      features += ";qHostInfo+";
    }
    if (target_.process) {
      features += ";qProcessInfo+";
    }
    if (target_.memory_layout) {
      features += ";qMemoryRegionInfo+";
    }
    if (target_.memory_layout && target_.memory_layout->has_memory_map()) {
      features += ";qXfer:memory-map:read+";
    }
    if (target_.libraries) {
      features += ";qXfer:libraries:read+";
    }
    send_packet(features);
    return;
  }

  if (name == "GDBServerVersion") {
    std::string response = "name:gdbstub_cpp;version:";
    response += gdbstub::version();
    response += ";";
    send_packet(response);
    return;
  }

  if (name == "StructuredDataPlugins") {
    send_packet("[]");
    return;
  }

  if (name.rfind("RegisterInfo", 0) == 0) {
    handle_register_info(name.substr(std::string_view("RegisterInfo").size()));
    return;
  }

  if (name.rfind("ThreadStopInfo", 0) == 0) {
    auto tid_str = name.substr(std::string_view("ThreadStopInfo").size());
    uint64_t tid = 0;
    if (tid_str.empty() || !parse_hex_u64(tid_str, tid)) {
      send_error(0x16);
      return;
    }
    std::optional<stop_reason> reason;
    if (target_.threads) {
      reason = target_.threads->thread_stop_reason(tid);
    }
    auto reply = reason.value_or(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
    reply.thread_id = tid;
    send_stop_reply(reply);
    return;
  }

  if (name == "ShlibInfoAddr") {
    handle_shlib_info_addr();
    return;
  }

  if (name == "Offsets") {
    handle_offsets();
    return;
  }

  if (name == "Attached") {
    send_packet(attached_state_ == attached_state::launched ? "0" : "1");
    return;
  }

  if (name == "C") {
    auto tid = current_thread_id().value_or(1);
    send_packet("QC" + hex_u64(tid));
    return;
  }

  if (name == "fThreadInfo") {
    send_packet(build_thread_list(thread_ids()));
    return;
  }

  if (name == "sThreadInfo") {
    send_packet("l");
    return;
  }

  if (name == "Symbol") {
    send_packet("OK");
    return;
  }

  if (name == "HostInfo") {
    handle_host_info();
    return;
  }

  if (name == "ProcessInfo") {
    handle_process_info();
    return;
  }

  if (name == "FileLoadAddress") {
    if (!target_.libraries) {
      send_packet("");
      return;
    }

    std::string decoded;
    if (!decode_hex_string(params, decoded)) {
      send_error(0x16);
      return;
    }

    bool case_insensitive = false;
    if (target_.process) {
      if (auto info = target_.process->get_process_info()) {
        case_insensitive = info->ostype == "windows";
      }
    }

    auto query_norm = normalize_path(decoded, case_insensitive);
    auto query_base = basename(query_norm);
    for (const auto& lib : target_.libraries->libraries()) {
      if (lib.name.empty() || lib.addresses.empty()) {
        continue;
      }
      auto lib_norm = normalize_path(lib.name, case_insensitive);
      if (lib_norm == query_norm || basename(lib_norm) == query_base) {
        send_packet(hex_u64(lib.addresses.front()));
        return;
      }
    }

    send_packet("");
    return;
  }

  if (name == "MemoryRegionInfo") {
    handle_memory_region_info(params);
    return;
  }

  send_packet("");
}

void server::handle_set_query(std::string_view args) {
  if (args == "StartNoAckMode") {
    send_packet("OK");
    no_ack_mode_ = true;
    return;
  }

  if (args == "ListThreadsInStopReply") {
    list_threads_in_stop_reply_ = true;
    send_packet("OK");
    return;
  }

  if (args == "ThreadSuffixSupported") {
    thread_suffix_enabled_ = true;
    send_packet("OK");
    return;
  }

  if (args.rfind("NonStop:", 0) == 0) {
    if (!run_caps().non_stop) {
      send_packet("");
      return;
    }
    if (args.size() != 9 || (args[8] != '0' && args[8] != '1')) {
      send_error(0x16);
      return;
    }
    non_stop_.enabled = args[8] == '1';
    reset_non_stop_state();
    send_packet("OK");
    return;
  }

  if (args.rfind("EnableErrorStrings", 0) == 0) {
    error_strings_enabled_ = true;
    send_packet("OK");
    return;
  }

  send_packet("");
}

void server::handle_v_packet(std::string_view args) {
  if (args == "Cont?") {
    auto caps = run_caps();
    std::string response = "vCont;c;C;s;S";
    if (caps.range_step) {
      response += ";r";
    }
    if (caps.non_stop) {
      response += ";t";
    }
    send_packet(response);
    return;
  }

  if (args.rfind("Run", 0) == 0) {
    handle_vrun(args.substr(3));
    return;
  }

  if (args.rfind("Attach;", 0) == 0) {
    handle_vattach(args.substr(7));
    return;
  }

  if (args.rfind("Kill", 0) == 0) {
    handle_vkill(args.substr(4));
    return;
  }

  if (args == "Stopped") {
    if (!non_stop_.enabled) {
      send_packet("");
      return;
    }
    std::optional<stop_reason> reason;
    {
      std::lock_guard<std::mutex> lock(non_stop_.mutex);
      if (!non_stop_.pending_stops.empty()) {
        reason = std::move(non_stop_.pending_stops.front());
        non_stop_.pending_stops.pop();
      }
    }
    if (!reason) {
      non_stop_.notification_in_flight = false;
      send_packet("OK");
      return;
    }
    bool include_library = consume_library_change();
    send_packet(build_stop_reply_payload(*reason, include_library));
    return;
  }

  if (args == "CtrlC") {
    handle_interrupt();
    send_packet("OK");
    return;
  }

  if (args.rfind("Cont;", 0) != 0) {
    send_packet("");
    return;
  }

  auto actions = args.substr(5);
  uint64_t current_tid = current_thread_id().value_or(1);
  vcont_selection selection;
  auto parse_result = parse_vcont_actions(actions, current_tid, selection);
  if (parse_result == vcont_parse_result::invalid) {
    send_error(0x16);
    return;
  }
  if (parse_result == vcont_parse_result::none) {
    send_stop_reply(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
    return;
  }

  auto caps = run_caps();

  if (selection.action == 't') {
    if (!non_stop_.enabled) {
      send_packet("");
      return;
    }
    non_stop_.stop_signal_zero_pending = true;
    target_.run.interrupt();
    send_packet("OK");
    return;
  }

  if (selection.action == 's' || selection.action == 'S') {
    auto result = target_.run.resume(resume_request::step(selection.signal));
    finish_resume(result, false);
    return;
  }

  if (selection.action == 'c' || selection.action == 'C') {
    auto result = target_.run.resume(resume_request::cont(selection.signal));
    finish_resume(result, false);
    return;
  }

  if (selection.action == 'r') {
    if (!caps.range_step) {
      send_packet("");
      return;
    }
    if (!selection.range) {
      send_error(0x16);
      return;
    }
    auto result = target_.run.resume(resume_request::range_step(*selection.range));
    finish_resume(result, true);
    return;
  }

  send_stop_reply(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
}

void server::handle_j_packet(std::string_view payload) {
  if (payload.rfind("jThreadsInfo", 0) == 0) {
    handle_threads_info();
    return;
  }

  if (payload.rfind("jThreadExtendedInfo:", 0) == 0) {
    handle_thread_extended_info(payload.substr(std::string_view("jThreadExtendedInfo:").size()));
    return;
  }

  if (payload.rfind("jGetLoadedDynamicLibrariesInfos", 0) == 0) {
    auto pos = payload.find(':');
    std::string_view args;
    if (pos != std::string_view::npos) {
      args = payload.substr(pos + 1);
    }
    handle_loaded_dynamic_libraries_infos(args);
    return;
  }

  send_packet("");
}

void server::handle_loaded_dynamic_libraries_infos(std::string_view args) {
  if (!target_.lldb) {
    send_packet("");
    return;
  }

  if (args.empty()) {
    send_packet("OK");
    return;
  }

  std::string request(args);
  rsp::unescape_binary(request);

  lldb::loaded_libraries_request parsed{};
  bool report_load_commands = true;
  if (parse_json_bool(request, "report_load_commands", report_load_commands)) {
    parsed.report_load_commands = report_load_commands;
  }

  bool fetch_all = false;
  if (parse_json_bool(request, "fetch_all_solibs", fetch_all) && fetch_all) {
    parsed.kind = lldb::loaded_libraries_request::kind::all;
  }

  std::vector<uint64_t> addresses;
  if (parse_json_u64_list(request, "solib_addresses", addresses)) {
    parsed.kind = lldb::loaded_libraries_request::kind::addresses;
    parsed.addresses = std::move(addresses);
  }

  auto image_count = parse_json_u64(request, "image_count");
  auto image_list_address = parse_json_u64(request, "image_list_address");
  if (image_count && image_list_address) {
    parsed.kind = lldb::loaded_libraries_request::kind::image_list;
    parsed.image_count = *image_count;
    parsed.image_list_address = *image_list_address;
  }

  auto payload = target_.lldb->loaded_libraries_json(parsed);
  if (!payload) {
    send_packet("");
    return;
  }

  auto escaped = rsp::escape_binary(as_bytes(*payload));
  send_packet(escaped);
}

void server::handle_xfer(std::string_view args) {
  constexpr std::string_view k_features_prefix = "features:read:";
  if (args.rfind(k_features_prefix, 0) == 0) {
    auto rest = args.substr(k_features_prefix.size());
    auto annex_end = rest.find(':');
    if (annex_end == std::string_view::npos) {
      send_error(0x01);
      return;
    }
    auto annex = rest.substr(0, annex_end);
    auto range = rest.substr(annex_end + 1);
    auto resolved_annex = annex.empty() ? std::string_view("target.xml") : annex;
    if (resolved_annex != "target.xml") {
      send_packet("");
      return;
    }
    if (arch_.target_xml.empty()) {
      send_error(0x01);
      return;
    }

    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    if (offset >= arch_.target_xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = arch_.target_xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));

    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= arch_.target_xml.size() ? 'l' : 'm');
    response.append(arch_.target_xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  constexpr std::string_view k_memory_map_prefix = "memory-map:read::";
  if (args.rfind(k_memory_map_prefix, 0) == 0) {
    if (!target_.memory_layout || !target_.memory_layout->has_memory_map()) {
      send_packet("");
      return;
    }

    auto range = args.substr(k_memory_map_prefix.size());
    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    auto xml = build_memory_map_xml(target_.memory_layout->memory_map());
    if (offset >= xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));
    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= xml.size() ? 'l' : 'm');
    response.append(xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  constexpr std::string_view k_libraries_prefix = "libraries:read::";
  if (args.rfind(k_libraries_prefix, 0) == 0) {
    if (!target_.libraries) {
      send_packet("");
      return;
    }

    auto range = args.substr(k_libraries_prefix.size());
    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    auto xml = build_library_list_xml(target_.libraries->libraries());
    if (offset >= xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));
    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= xml.size() ? 'l' : 'm');
    response.append(xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  send_packet("");
}

void server::handle_host_info() {
  if (!target_.host) {
    send_packet("");
    return;
  }

  auto info = target_.host->get_host_info();
  if (!info) {
    send_packet("");
    return;
  }

  std::string response;
  response.reserve(128);
  response += "triple:" + hex_encode_string(info->triple) + ";";
  response += "ptrsize:" + std::to_string(info->ptr_size) + ";";
  response += "endian:" + info->endian + ";";
  response += "hostname:" + hex_encode_string(info->hostname) + ";";

  if (info->os_version) {
    response += "os_version:" + *info->os_version + ";";
  }
  if (info->os_build) {
    response += "os_build:" + hex_encode_string(*info->os_build) + ";";
  }
  if (info->os_kernel) {
    response += "os_kernel:" + hex_encode_string(*info->os_kernel) + ";";
  }
  if (info->addressing_bits) {
    response += "addressing_bits:" + std::to_string(*info->addressing_bits) + ";";
  }
  if (info->low_mem_addressing_bits) {
    response += "low_mem_addressing_bits:" + std::to_string(*info->low_mem_addressing_bits) + ";";
  }
  if (info->high_mem_addressing_bits) {
    response += "high_mem_addressing_bits:" + std::to_string(*info->high_mem_addressing_bits) + ";";
  }

  send_packet(response);
}

void server::handle_process_info() {
  if (!target_.process) {
    send_packet("");
    return;
  }

  auto info = target_.process->get_process_info();
  if (!info) {
    send_error(0x0e);
    return;
  }

  std::string response;
  response.reserve(128);
  response += "pid:" + hex_u64(static_cast<uint64_t>(info->pid)) + ";";
  response += "triple:" + hex_encode_string(info->triple) + ";";
  response += "endian:" + info->endian + ";";
  response += "ptrsize:" + std::to_string(info->ptr_size) + ";";
  response += "ostype:" + info->ostype + ";";
  if (target_.lldb) {
    if (auto extras = target_.lldb->process_info_extras()) {
      for (const auto& pair : *extras) {
        if (pair.key.empty()) {
          continue;
        }
        response += pair.key;
        response += ":";
        switch (pair.encoding) {
        case lldb::kv_encoding::raw:
          response += pair.value;
          break;
        case lldb::kv_encoding::hex_string:
          response += hex_encode_string(pair.value);
          break;
        case lldb::kv_encoding::hex_u64:
          response += hex_u64(pair.u64_value);
          break;
        case lldb::kv_encoding::dec_u64:
          response += std::to_string(pair.u64_value);
          break;
        }
        response += ";";
      }
    }
  }
  send_packet(response);
}

void server::handle_shlib_info_addr() {
  if (!target_.shlib) {
    send_packet("");
    return;
  }

  auto info = target_.shlib->get_shlib_info();
  if (!info || !info->info_addr) {
    send_packet("");
    return;
  }

  size_t addr_size = 0;
  if (target_.host) {
    if (auto host = target_.host->get_host_info()) {
      if (host->ptr_size > 0) {
        addr_size = static_cast<size_t>(host->ptr_size);
      }
    }
  }
  if (addr_size == 0 && arch_.pc_reg_num >= 0) {
    addr_size = target_.regs.reg_size(arch_.pc_reg_num);
  }
  if (addr_size == 0 || addr_size > sizeof(uint64_t)) {
    addr_size = sizeof(uint64_t);
  }

  std::vector<std::byte> buffer(addr_size);
  uint64_t addr = *info->info_addr;
  for (size_t i = 0; i < addr_size; ++i) {
    size_t shift = (addr_size - 1 - i) * 8;
    buffer[i] = std::byte(static_cast<uint8_t>((addr >> shift) & 0xff));
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_offsets() {
  if (!target_.offsets) {
    send_packet("");
    return;
  }

  auto info = target_.offsets->get_offsets_info();
  if (!info) {
    send_packet("");
    return;
  }

  std::string response;
  switch (info->kind) {
  case offsets_kind::section:
    if (!info->data) {
      send_packet("");
      return;
    }
    response = "Text=" + hex_u64(info->text) + ";Data=" + hex_u64(*info->data);
    if (info->bss) {
      response += ";Bss=" + hex_u64(*info->bss);
    }
    break;
  case offsets_kind::segment:
    if (info->bss) {
      send_packet("");
      return;
    }
    response = "TextSeg=" + hex_u64(info->text);
    if (info->data) {
      response += ";DataSeg=" + hex_u64(*info->data);
    }
    break;
  default:
    send_packet("");
    return;
  }

  send_packet(response);
}

} // namespace gdbstub
