#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <optional>
#include <thread>

#include "gdbstub/target.hpp"
#include "gdbstub_tool/toy/machine.hpp"
#include "gdbstub_tool/toy/threads.hpp"
#include "gdbstub_tool/toy/types.hpp"

namespace gdbstub::toy {

class stop_tracker {
public:
  void set_notifier(stop_notifier notifier) {
    std::lock_guard<std::mutex> lock(mutex_);
    notifier_ = notifier;
  }

  void record_stop(const stop_reason& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_stop_ = reason;
  }

  void queue_stop(const stop_reason& reason) {
    stop_notifier notifier;
    bool notify = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      last_stop_ = reason;
      if (!pending_stop_) {
        pending_stop_ = reason;
        notifier = notifier_;
        notify = true;
      }
    }
    if (notify && notifier.notify) {
      notifier(reason);
    }
  }

  std::optional<stop_reason> take_pending() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!pending_stop_) {
      return std::nullopt;
    }
    auto stop = pending_stop_;
    pending_stop_.reset();
    return stop;
  }

  std::optional<stop_reason> last_stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_stop_;
  }

private:
  std::mutex mutex_;
  std::optional<stop_reason> pending_stop_;
  std::optional<stop_reason> last_stop_;
  stop_notifier notifier_{};
};

// Drives execution modes and reverse history for the toy target.
class runner {
public:
  runner(machine& machine, threads& threads, execution_mode mode, size_t max_steps, size_t history_limit)
      : machine_(machine),
        threads_(threads),
        mode_(mode),
        max_steps_(max_steps),
        history_limit_(history_limit) {}

  ~runner() { stop_async(); }

  void set_mode(execution_mode mode) { mode_ = mode; }
  execution_mode mode() const { return mode_; }

  void set_max_steps(size_t max_steps) { max_steps_ = max_steps; }
  size_t max_steps() const { return max_steps_; }

  void set_stop_notifier(stop_notifier notifier) { stops_.set_notifier(notifier); }

  run_capabilities capabilities() const {
    run_capabilities caps;
    bool has_history = history_limit_ > 0;
    caps.reverse_continue = has_history;
    caps.reverse_step = has_history;
    caps.range_step = true;
    caps.non_stop = mode_ != execution_mode::blocking;
    return caps;
  }

  resume_result resume(const resume_request& request) {
    const auto thread_id = threads_.current_thread();
    apply_resume_address(request);

    if (request.direction == resume_direction::reverse) {
      return resume_reverse(request, thread_id);
    }
    return resume_forward(request, thread_id);
  }

  void interrupt() {
    stop_requested_.store(true);
    running_.store(false);
    stops_.queue_stop(signal_stop(threads_.current_thread()));
  }

  std::optional<stop_reason> poll_stop() {
    if (auto pending = stops_.take_pending()) {
      return pending;
    }

    if (mode_ != execution_mode::polling || !running_.load()) {
      return std::nullopt;
    }

    if (auto stop = forward_step(threads_.current_thread())) {
      running_.store(false);
      stops_.record_stop(*stop);
      return stop;
    }

    return std::nullopt;
  }

  std::optional<stop_reason> last_stop() { return stops_.last_stop(); }

private:
  void apply_resume_address(const resume_request& request) {
    if (request.addr) {
      machine_.set_pc(*request.addr);
    }
  }

  resume_result make_error(target_status status) {
    resume_result result;
    result.status = status;
    return result;
  }

  resume_result make_running() {
    resume_result result;
    result.state = resume_result::state::running;
    return result;
  }

  resume_result make_stopped(const stop_reason& stop) {
    stops_.record_stop(stop);
    resume_result result;
    result.state = resume_result::state::stopped;
    result.stop = stop;
    return result;
  }

  resume_result resume_forward(const resume_request& request, uint64_t thread_id) {
    switch (request.action) {
      case resume_action::range_step:
        if (!request.range) {
          return make_error(target_status::invalid);
        }
        return run_range_blocking(thread_id, *request.range);
      case resume_action::step:
        return run_step(thread_id);
      case resume_action::cont:
      default:
        return resume_continue(thread_id);
    }
  }

  resume_result resume_continue(uint64_t thread_id) {
    switch (mode_) {
      case execution_mode::blocking:
        return make_stopped(run_blocking(thread_id));
      case execution_mode::polling:
        running_.store(true);
        return make_running();
      case execution_mode::async:
        start_async(thread_id);
        return make_running();
    }
    return make_stopped(signal_stop(thread_id));
  }

  void record_snapshot() {
    if (history_limit_ == 0) {
      return;
    }
    auto snap = machine_.capture_snapshot();
    std::lock_guard<std::mutex> lock(history_mutex_);
    history_.push_back(std::move(snap));
    if (history_.size() > history_limit_) {
      history_.pop_front();
    }
  }

  std::optional<machine::snapshot> pop_snapshot() {
    std::lock_guard<std::mutex> lock(history_mutex_);
    if (history_.empty()) {
      return std::nullopt;
    }
    auto snap = std::move(history_.back());
    history_.pop_back();
    return snap;
  }

  std::optional<stop_reason> forward_step(uint64_t thread_id) {
    record_snapshot();
    machine_.advance_pc();
    auto pc = machine_.pc();
    auto [read_addr, write_addr] = machine_.access_addrs_for_pc(pc);
    if (auto stop = machine_.stop_if_watchpoint(thread_id, read_addr, write_addr)) {
      return stop;
    }
    return machine_.stop_if_breakpoint(thread_id);
  }

  resume_result run_step(uint64_t thread_id) {
    if (auto stop = forward_step(thread_id)) {
      return make_stopped(*stop);
    }
    return make_stopped(signal_stop(thread_id));
  }

  resume_result run_range_blocking(uint64_t thread_id, const address_range& range) {
    auto in_range = [&](uint64_t value) { return value >= range.start && value < range.end; };

    auto step_stop = forward_step(thread_id);
    if (step_stop) {
      return make_stopped(*step_stop);
    }

    if (range.start == range.end) {
      return make_stopped(signal_stop(thread_id));
    }

    if (!in_range(machine_.pc())) {
      return make_stopped(signal_stop(thread_id));
    }

    for (size_t i = 0; i < max_steps_; ++i) {
      if (!in_range(machine_.pc())) {
        return make_stopped(signal_stop(thread_id));
      }
      if (auto stop = forward_step(thread_id)) {
        return make_stopped(*stop);
      }
    }

    return make_stopped(signal_stop(thread_id));
  }

  resume_result resume_reverse(const resume_request& request, uint64_t thread_id) {
    if (history_limit_ == 0) {
      return make_error(target_status::unsupported);
    }

    switch (request.action) {
      case resume_action::range_step:
        return make_error(target_status::unsupported);
      case resume_action::step:
        return reverse_step(thread_id);
      case resume_action::cont:
      default:
        return reverse_continue(thread_id);
    }
  }

  stop_reason replay_log_begin_stop(uint64_t thread_id) const {
    stop_reason stop;
    stop.kind = stop_kind::signal;
    stop.signal = 5;
    stop.thread_id = thread_id;
    stop.replay_log = replay_log_boundary::begin;
    return stop;
  }

  std::optional<stop_reason> restore_previous(uint64_t thread_id) {
    auto snap = pop_snapshot();
    if (!snap) {
      return replay_log_begin_stop(thread_id);
    }
    machine_.restore_snapshot(*snap);
    return machine_.stop_if_breakpoint(thread_id);
  }

  resume_result reverse_step(uint64_t thread_id) {
    if (auto stop = restore_previous(thread_id)) {
      return make_stopped(*stop);
    }
    return make_stopped(signal_stop(thread_id));
  }

  resume_result reverse_continue(uint64_t thread_id) {
    for (size_t i = 0; i < max_steps_; ++i) {
      if (auto stop = restore_previous(thread_id)) {
        return make_stopped(*stop);
      }
    }
    return make_stopped(signal_stop(thread_id));
  }

  stop_reason run_blocking(uint64_t thread_id) {
    for (size_t i = 0; i < max_steps_; ++i) {
      if (auto stop = forward_step(thread_id)) {
        return *stop;
      }
    }
    return signal_stop(thread_id);
  }

  void start_async(uint64_t thread_id) {
    stop_async();
    stop_requested_.store(false);
    running_.store(true);
    worker_ = std::thread([this, thread_id]() {
      for (size_t i = 0; i < max_steps_; ++i) {
        if (stop_requested_.load()) {
          stops_.queue_stop(signal_stop(thread_id));
          running_.store(false);
          return;
        }
        if (auto stop = forward_step(thread_id)) {
          stops_.queue_stop(*stop);
          running_.store(false);
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      stops_.queue_stop(signal_stop(thread_id));
      running_.store(false);
    });
  }

  void stop_async() {
    stop_requested_.store(true);
    if (worker_.joinable()) {
      worker_.join();
    }
    running_.store(false);
  }

  stop_reason signal_stop(uint64_t thread_id) const { return machine_.signal_stop(thread_id); }

  machine& machine_;
  threads& threads_;
  execution_mode mode_ = execution_mode::blocking;
  size_t max_steps_ = 0;
  size_t history_limit_ = 0;

  stop_tracker stops_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::thread worker_;
  std::deque<machine::snapshot> history_;
  std::mutex history_mutex_;
};

} // namespace gdbstub::toy
