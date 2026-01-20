#include "gdbstub/server/server.hpp"

#include <algorithm>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

void server::handle_set_thread(std::string_view args) {
  if (args.size() < 2) {
    send_error(0x16);
    return;
  }

  auto thread_str = args.substr(1);
  std::optional<uint64_t> tid;
  if (!parse_thread_token(thread_str, tid)) {
    send_error(0x16);
    return;
  }

  if (target_.threads && tid) {
    target_.threads->set_current_thread(*tid);
  }

  send_packet("OK");
}

void server::handle_thread_alive(std::string_view args) {
  uint64_t tid = 0;
  if (!parse_hex_u64(args, tid)) {
    send_error(0x16);
    return;
  }

  if (target_.threads) {
    auto ids = target_.threads->thread_ids();
    if (std::find(ids.begin(), ids.end(), tid) == ids.end()) {
      send_error(0x16);
      return;
    }
  }

  send_packet("OK");
}

void server::handle_threads_info() {
  if (!target_.threads) {
    send_packet("");
    return;
  }

  auto ids = thread_ids();
  std::string json;
  json.reserve(64 + ids.size() * 32);
  json.push_back('[');
  for (size_t i = 0; i < ids.size(); ++i) {
    if (i > 0) {
      json.push_back(',');
    }
    json.push_back('{');
    json += "\"tid\":";
    json += std::to_string(ids[i]);

    std::optional<stop_reason> reason;
    if (target_.threads) {
      reason = target_.threads->thread_stop_reason(ids[i]);
    }
    if (!reason && last_stop_ && (!last_stop_->thread_id || *last_stop_->thread_id == ids[i])) {
      reason = last_stop_;
    }
    if (reason) {
      json += ",\"reason\":\"";
      json += stop_reason_label(reason->kind);
      json += "\"";
      if (reason->signal > 0) {
        json += ",\"signal\":";
        json += std::to_string(reason->signal);
      }
    }

    json.push_back('}');
  }
  json.push_back(']');

  auto escaped = rsp::escape_binary(as_bytes(json));
  send_packet(escaped);
}

void server::handle_thread_extended_info(std::string_view args) {
  if (!target_.threads) {
    send_packet("");
    return;
  }

  std::string request(args);
  rsp::unescape_binary(request);
  auto tid = parse_json_thread_id(request);
  if (!tid) {
    send_error(0x16);
    return;
  }

  auto ids = thread_ids();
  if (!ids.empty() && std::find(ids.begin(), ids.end(), *tid) == ids.end()) {
    send_error(0x16);
    return;
  }

  std::string json;
  json.reserve(64);
  json.push_back('{');
  json += "\"thread\":";
  json += std::to_string(*tid);

  if (auto name = target_.threads->thread_name(*tid)) {
    json += ",\"name\":\"";
    json += escape_json_string(*name);
    json += "\"";
  }

  if (auto reason = target_.threads->thread_stop_reason(*tid)) {
    json += ",\"reason\":\"";
    json += stop_reason_label(reason->kind);
    json += "\"";
    if (reason->signal > 0) {
      json += ",\"signal\":";
      json += std::to_string(reason->signal);
    }
  }

  json.push_back('}');

  auto escaped = rsp::escape_binary(as_bytes(json));
  send_packet(escaped);
}

std::optional<uint64_t> server::current_thread_id() const {
  if (target_.threads) {
    return target_.threads->current_thread();
  }
  return std::nullopt;
}

std::vector<uint64_t> server::thread_ids() const {
  if (target_.threads) {
    auto ids = target_.threads->thread_ids();
    if (!ids.empty()) {
      return ids;
    }
  }
  return {current_thread_id().value_or(1)};
}

} // namespace gdbstub
