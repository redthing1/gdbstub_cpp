#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <vector>

#include "gdbstub/rsp_core.hpp"
#include "gdbstub/rsp_types.hpp"
#include "gdbstub/target.hpp"
#include "gdbstub/transport.hpp"

namespace gdbstub {

struct arch_spec {
  std::string target_xml;
  std::string xml_arch_name;
  std::string osabi;
  int reg_count = 0;
  int pc_reg_num = -1;
  std::optional<int> address_bits;
  bool swap_register_endianness = false;
};

class server {
public:
  server(target target, arch_spec arch, std::unique_ptr<transport> transport);
  ~server();

  bool listen(std::string_view address);
  bool wait_for_connection();
  bool has_connection() const;
  void serve_forever();
  bool poll(std::chrono::milliseconds timeout);
  void notify_stop(stop_reason reason);
  void stop();

private:
  enum class exec_state { halted, running };

  struct non_stop_state {
    bool enabled = false;
    bool notification_in_flight = false;
    bool stop_signal_zero_pending = false;
    std::mutex mutex;
    std::queue<stop_reason> pending_stops;
  };

  target_view target_;
  arch_spec arch_;
  std::unique_ptr<transport> transport_;
  rsp::stream_parser parser_;

  exec_state exec_state_ = exec_state::halted;
  bool no_ack_mode_ = false;
  bool list_threads_in_stop_reply_ = false;
  bool thread_suffix_enabled_ = false;
  bool error_strings_enabled_ = false;
  non_stop_state non_stop_;
  std::optional<stop_reason> last_stop_;

  bool read_and_process(std::chrono::milliseconds timeout);
  bool process_event(const rsp::input_event& event);
  bool flush_pending_stop();

  void handle_interrupt();
  void handle_packet(std::string_view payload);
  void handle_query(std::string_view args);
  void handle_set_query(std::string_view args);
  void handle_v_packet(std::string_view args);
  void handle_continue(std::string_view args, resume_action action, bool has_signal);
  void handle_reverse(bool step);
  void finish_resume(const resume_result& result, bool optional_feature);
  void handle_read_all_registers();
  void handle_write_all_registers(std::string_view args);
  void handle_read_register(std::string_view args);
  void handle_write_register(std::string_view args);
  void handle_register_info(std::string_view args);
  void handle_read_memory(std::string_view args);
  void handle_read_binary_memory(std::string_view args);
  void handle_write_memory(std::string_view args);
  void handle_write_binary_memory(std::string_view args);
  void handle_insert_breakpoint(std::string_view args);
  void handle_remove_breakpoint(std::string_view args);
  void handle_set_thread(std::string_view args);
  void handle_thread_alive(std::string_view args);
  void handle_halt_reason();
  void handle_detach();
  void handle_extended_mode();
  void handle_j_packet(std::string_view payload);
  void handle_xfer(std::string_view args);
  void handle_host_info();
  void handle_process_info();
  void handle_memory_region_info(std::string_view addr_str);
  void handle_shlib_info_addr();
  void handle_threads_info();
  void handle_thread_extended_info(std::string_view args);

  void send_ack();
  void send_nack();
  void send_packet(std::string_view payload);
  void send_notification(std::string_view payload);
  void send_error(uint8_t code);
  void send_status_error(target_status status, bool optional_feature);
  void send_stop_reply(const stop_reason& reason);
  void send_exit_reply(const stop_reason& reason);
  std::string build_stop_reply_payload(const stop_reason& reason) const;
  void maybe_send_stop_notification();
  void enqueue_stop(stop_reason reason);
  void reset_non_stop_state();
  bool supports_sw_break() const;
  bool supports_hw_break() const;

  std::optional<uint64_t> current_thread_id() const;
  std::vector<uint64_t> thread_ids() const;
  run_capabilities run_caps() const;
  breakpoint_capabilities breakpoint_caps() const;
};

} // namespace gdbstub
