module gdbstub_cpp_c_api;

import core.stdc.stdint : uint32_t, uint64_t, uint8_t;

extern(C):

struct gdbstub_string_view {
    const(char)* data;
    size_t size;
}

struct gdbstub_slice_string {
    const(gdbstub_string_view)* data;
    size_t len;
}

struct gdbstub_slice_u64 {
    const(uint64_t)* data;
    size_t len;
}

struct gdbstub_slice_int {
    const(int)* data;
    size_t len;
}

struct gdbstub_slice_region {
    const(gdbstub_memory_region)* data;
    size_t len;
}

enum gdbstub_stop_kind : int {
    GDBSTUB_STOP_SIGNAL = 0,
    GDBSTUB_STOP_SW_BREAK = 1,
    GDBSTUB_STOP_HW_BREAK = 2,
    GDBSTUB_STOP_WATCH_READ = 3,
    GDBSTUB_STOP_WATCH_WRITE = 4,
    GDBSTUB_STOP_WATCH_ACCESS = 5,
    GDBSTUB_STOP_EXITED = 6,
}

enum gdbstub_replay_log_boundary : int {
    GDBSTUB_REPLAY_LOG_BEGIN = 0,
    GDBSTUB_REPLAY_LOG_END = 1,
}

enum gdbstub_resume_direction : int {
    GDBSTUB_RESUME_FORWARD = 0,
    GDBSTUB_RESUME_REVERSE = 1,
}

enum gdbstub_resume_action : int {
    GDBSTUB_RESUME_CONT = 0,
    GDBSTUB_RESUME_STEP = 1,
    GDBSTUB_RESUME_RANGE_STEP = 2,
}

enum gdbstub_target_status : int {
    GDBSTUB_TARGET_OK = 0,
    GDBSTUB_TARGET_FAULT = 1,
    GDBSTUB_TARGET_INVALID = 2,
    GDBSTUB_TARGET_UNSUPPORTED = 3,
}

enum gdbstub_resume_state : int {
    GDBSTUB_RESUME_STOPPED = 0,
    GDBSTUB_RESUME_RUNNING = 1,
    GDBSTUB_RESUME_EXITED = 2,
}

enum gdbstub_mem_perm : uint8_t {
    GDBSTUB_MEM_PERM_NONE = 0,
    GDBSTUB_MEM_PERM_READ = 1,
    GDBSTUB_MEM_PERM_WRITE = 2,
    GDBSTUB_MEM_PERM_EXEC = 4,
}

enum gdbstub_breakpoint_type : int {
    GDBSTUB_BREAKPOINT_SOFTWARE = 0,
    GDBSTUB_BREAKPOINT_HARDWARE = 1,
    GDBSTUB_BREAKPOINT_WATCH_WRITE = 2,
    GDBSTUB_BREAKPOINT_WATCH_READ = 3,
    GDBSTUB_BREAKPOINT_WATCH_ACCESS = 4,
}

struct gdbstub_stop_reason {
    gdbstub_stop_kind kind;
    int signal;
    uint64_t addr;
    int exit_code;
    uint8_t has_thread_id;
    uint64_t thread_id;
    uint8_t has_replay_log;
    gdbstub_replay_log_boundary replay_log;
}

struct gdbstub_address_range {
    uint64_t start;
    uint64_t end;
}

struct gdbstub_resume_request {
    gdbstub_resume_action action;
    gdbstub_resume_direction direction;
    uint8_t has_addr;
    uint64_t addr;
    uint8_t has_signal;
    int signal;
    uint8_t has_range;
    gdbstub_address_range range;
}

struct gdbstub_resume_result {
    gdbstub_resume_state state;
    gdbstub_stop_reason stop;
    int exit_code;
    gdbstub_target_status status;
}

struct gdbstub_breakpoint_spec {
    gdbstub_breakpoint_type type;
    uint64_t addr;
    uint32_t length;
}

struct gdbstub_memory_region {
    uint64_t start;
    uint64_t size;
    uint8_t perms;
    uint8_t has_name;
    gdbstub_string_view name;
    gdbstub_slice_string types;
}

struct gdbstub_memory_region_info {
    uint64_t start;
    uint64_t size;
    uint8_t mapped;
    uint8_t perms;
    uint8_t has_name;
    gdbstub_string_view name;
    gdbstub_slice_string types;
}

struct gdbstub_host_info {
    gdbstub_string_view triple;
    gdbstub_string_view endian;
    int ptr_size;
    gdbstub_string_view hostname;
    uint8_t has_os_version;
    gdbstub_string_view os_version;
    uint8_t has_os_build;
    gdbstub_string_view os_build;
    uint8_t has_os_kernel;
    gdbstub_string_view os_kernel;
    uint8_t has_addressing_bits;
    int addressing_bits;
}

struct gdbstub_process_info {
    int pid;
    gdbstub_string_view triple;
    gdbstub_string_view endian;
    int ptr_size;
    gdbstub_string_view ostype;
}

struct gdbstub_shlib_info {
    uint8_t has_info_addr;
    uint64_t info_addr;
}

struct gdbstub_process_launch_request {
    uint8_t has_filename;
    gdbstub_string_view filename;
    const(gdbstub_string_view)* args;
    size_t args_len;
}

enum gdbstub_offsets_kind : int {
    GDBSTUB_OFFSETS_SECTION = 0,
    GDBSTUB_OFFSETS_SEGMENT = 1,
}

struct gdbstub_offsets_info {
    gdbstub_offsets_kind kind;
    uint64_t text;
    uint8_t has_data;
    uint64_t data;
    uint8_t has_bss;
    uint64_t bss;
}

struct gdbstub_register_info {
    gdbstub_string_view name;
    uint8_t has_alt_name;
    gdbstub_string_view alt_name;
    int bitsize;
    uint8_t has_offset;
    size_t offset;
    gdbstub_string_view encoding;
    gdbstub_string_view format;
    uint8_t has_set;
    gdbstub_string_view set;
    uint8_t has_gcc_regnum;
    int gcc_regnum;
    uint8_t has_dwarf_regnum;
    int dwarf_regnum;
    uint8_t has_generic;
    gdbstub_string_view generic;
    gdbstub_slice_int container_regs;
    gdbstub_slice_int invalidate_regs;
}

struct gdbstub_arch_spec {
    gdbstub_string_view target_xml;
    gdbstub_string_view xml_arch_name;
    gdbstub_string_view osabi;
    int reg_count;
    int pc_reg_num;
    uint8_t has_address_bits;
    int address_bits;
    uint8_t swap_register_endianness;
}

alias gdbstub_stop_notify_fn = extern(C) void function(void* ctx, const(gdbstub_stop_reason)* reason);

struct gdbstub_stop_notifier {
    void* ctx;
    gdbstub_stop_notify_fn notify;
}

alias gdbstub_reg_size_fn = extern(C) size_t function(void* ctx, int regno);
alias gdbstub_read_reg_fn = extern(C) gdbstub_target_status function(
    void* ctx,
    int regno,
    uint8_t* buffer,
    size_t buffer_len
);
alias gdbstub_write_reg_fn = extern(C) gdbstub_target_status function(
    void* ctx,
    int regno,
    const(uint8_t)* data,
    size_t data_len
);

alias gdbstub_read_mem_fn = extern(C) gdbstub_target_status function(
    void* ctx,
    uint64_t addr,
    uint8_t* buffer,
    size_t buffer_len
);
alias gdbstub_write_mem_fn = extern(C) gdbstub_target_status function(
    void* ctx,
    uint64_t addr,
    const(uint8_t)* data,
    size_t data_len
);

alias gdbstub_resume_fn = extern(C) gdbstub_resume_result function(
    void* ctx,
    const(gdbstub_resume_request)* request
);
alias gdbstub_interrupt_fn = extern(C) void function(void* ctx);
alias gdbstub_poll_stop_fn = extern(C) uint8_t function(void* ctx, gdbstub_stop_reason* reason_out);
alias gdbstub_set_stop_notifier_fn = extern(C) void function(
    void* ctx,
    gdbstub_stop_notifier notifier
);

alias gdbstub_breakpoint_fn = extern(C) gdbstub_target_status function(
    void* ctx,
    const(gdbstub_breakpoint_spec)* spec
);

struct gdbstub_run_capabilities {
    uint8_t reverse_continue;
    uint8_t reverse_step;
    uint8_t range_step;
    uint8_t non_stop;
}

struct gdbstub_breakpoint_capabilities {
    uint8_t software;
    uint8_t hardware;
    uint8_t watch_read;
    uint8_t watch_write;
    uint8_t watch_access;
}

alias gdbstub_get_run_capabilities_fn = extern(C) uint8_t function(
    void* ctx,
    gdbstub_run_capabilities* caps_out
);

alias gdbstub_get_breakpoint_capabilities_fn = extern(C) uint8_t function(
    void* ctx,
    gdbstub_breakpoint_capabilities* caps_out
);

alias gdbstub_region_info_fn = extern(C) uint8_t function(
    void* ctx,
    uint64_t addr,
    gdbstub_memory_region_info* info_out
);

alias gdbstub_memory_map_fn = extern(C) gdbstub_slice_region function(void* ctx);

alias gdbstub_thread_ids_fn = extern(C) gdbstub_slice_u64 function(void* ctx);
alias gdbstub_current_thread_fn = extern(C) uint64_t function(void* ctx);
alias gdbstub_set_current_thread_fn = extern(C) gdbstub_target_status function(void* ctx, uint64_t tid);
alias gdbstub_thread_pc_fn = extern(C) uint8_t function(void* ctx, uint64_t tid, uint64_t* value_out);
alias gdbstub_thread_name_fn = extern(C) uint8_t function(
    void* ctx,
    uint64_t tid,
    gdbstub_string_view* name_out
);
alias gdbstub_thread_stop_reason_fn = extern(C) uint8_t function(
    void* ctx,
    uint64_t tid,
    gdbstub_stop_reason* reason_out
);

alias gdbstub_get_host_info_fn = extern(C) uint8_t function(void* ctx, gdbstub_host_info* info_out);
alias gdbstub_get_process_info_fn = extern(C) uint8_t function(void* ctx, gdbstub_process_info* info_out);
alias gdbstub_get_shlib_info_fn = extern(C) uint8_t function(void* ctx, gdbstub_shlib_info* info_out);
alias gdbstub_launch_fn = extern(C) gdbstub_resume_result function(void* ctx, const(gdbstub_process_launch_request)* req);
alias gdbstub_attach_fn = extern(C) gdbstub_resume_result function(void* ctx, uint64_t pid);
alias gdbstub_kill_fn = extern(C) gdbstub_target_status function(void* ctx, uint8_t has_pid, uint64_t pid);
alias gdbstub_restart_fn = extern(C) gdbstub_resume_result function(void* ctx);
alias gdbstub_get_offsets_info_fn = extern(C) uint8_t function(void* ctx, gdbstub_offsets_info* info_out);
alias gdbstub_get_register_info_fn = extern(C) uint8_t function(
    void* ctx,
    int regno,
    gdbstub_register_info* info_out
);

struct gdbstub_regs_iface {
    void* ctx;
    gdbstub_reg_size_fn reg_size;
    gdbstub_read_reg_fn read_reg;
    gdbstub_write_reg_fn write_reg;
}

struct gdbstub_mem_iface {
    void* ctx;
    gdbstub_read_mem_fn read_mem;
    gdbstub_write_mem_fn write_mem;
}

struct gdbstub_run_iface {
    void* ctx;
    gdbstub_resume_fn resume;
    gdbstub_interrupt_fn interrupt;
    gdbstub_poll_stop_fn poll_stop;
    gdbstub_set_stop_notifier_fn set_stop_notifier;
    gdbstub_get_run_capabilities_fn get_capabilities;
}

struct gdbstub_breakpoints_iface {
    void* ctx;
    gdbstub_breakpoint_fn set_breakpoint;
    gdbstub_breakpoint_fn remove_breakpoint;
    gdbstub_get_breakpoint_capabilities_fn get_capabilities;
}

struct gdbstub_memory_layout_iface {
    void* ctx;
    gdbstub_region_info_fn region_info;
    gdbstub_memory_map_fn memory_map;
}

struct gdbstub_threads_iface {
    void* ctx;
    gdbstub_thread_ids_fn thread_ids;
    gdbstub_current_thread_fn current_thread;
    gdbstub_set_current_thread_fn set_current_thread;
    gdbstub_thread_pc_fn thread_pc;
    gdbstub_thread_name_fn thread_name;
    gdbstub_thread_stop_reason_fn thread_stop_reason;
}

struct gdbstub_host_info_iface {
    void* ctx;
    gdbstub_get_host_info_fn get_host_info;
}

struct gdbstub_process_info_iface {
    void* ctx;
    gdbstub_get_process_info_fn get_process_info;
}

struct gdbstub_shlib_info_iface {
    void* ctx;
    gdbstub_get_shlib_info_fn get_shlib_info;
}

struct gdbstub_process_control_iface {
    void* ctx;
    gdbstub_launch_fn launch;
    gdbstub_attach_fn attach;
    gdbstub_kill_fn kill;
    gdbstub_restart_fn restart;
}

struct gdbstub_offsets_info_iface {
    void* ctx;
    gdbstub_get_offsets_info_fn get_offsets_info;
}

struct gdbstub_register_info_iface {
    void* ctx;
    gdbstub_get_register_info_fn get_register_info;
}

struct gdbstub_target_config {
    gdbstub_regs_iface regs;
    gdbstub_mem_iface mem;
    gdbstub_run_iface run;
    const(gdbstub_breakpoints_iface)* breakpoints;
    const(gdbstub_memory_layout_iface)* memory_layout;
    const(gdbstub_threads_iface)* threads;
    const(gdbstub_host_info_iface)* host;
    const(gdbstub_process_info_iface)* process;
    const(gdbstub_shlib_info_iface)* shlib;
    const(gdbstub_process_control_iface)* process_control;
    const(gdbstub_offsets_info_iface)* offsets;
    const(gdbstub_register_info_iface)* reg_info;
}

struct gdbstub_target {}
struct gdbstub_transport {}
struct gdbstub_server {}

gdbstub_string_view gdbstub_version();

gdbstub_transport* gdbstub_transport_tcp_create();
void gdbstub_transport_destroy(gdbstub_transport* transport);

gdbstub_target* gdbstub_target_create(const gdbstub_target_config* config);
void gdbstub_target_destroy(gdbstub_target* target);

gdbstub_server* gdbstub_server_create(
    gdbstub_target* target,
    gdbstub_arch_spec arch,
    gdbstub_transport* transport
);
void gdbstub_server_destroy(gdbstub_server* server);

uint8_t gdbstub_server_listen(gdbstub_server* server, gdbstub_string_view address);
uint8_t gdbstub_server_wait_for_connection(gdbstub_server* server);
uint8_t gdbstub_server_has_connection(gdbstub_server* server);
void gdbstub_server_serve_forever(gdbstub_server* server);
uint8_t gdbstub_server_poll(gdbstub_server* server, uint64_t timeout_ms);
void gdbstub_server_notify_stop(gdbstub_server* server, const(gdbstub_stop_reason)* reason);
void gdbstub_server_stop(gdbstub_server* server);
