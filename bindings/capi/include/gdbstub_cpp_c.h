#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gdbstub_string_view {
  const char* data;
  size_t size;
} gdbstub_string_view;

typedef struct gdbstub_slice_string {
  const gdbstub_string_view* data;
  size_t len;
} gdbstub_slice_string;

typedef struct gdbstub_slice_u64 {
  const uint64_t* data;
  size_t len;
} gdbstub_slice_u64;

typedef struct gdbstub_slice_int {
  const int* data;
  size_t len;
} gdbstub_slice_int;

typedef struct gdbstub_slice_region {
  const struct gdbstub_memory_region* data;
  size_t len;
} gdbstub_slice_region;

typedef enum gdbstub_stop_kind {
  GDBSTUB_STOP_SIGNAL = 0,
  GDBSTUB_STOP_SW_BREAK = 1,
  GDBSTUB_STOP_HW_BREAK = 2,
  GDBSTUB_STOP_WATCH_READ = 3,
  GDBSTUB_STOP_WATCH_WRITE = 4,
  GDBSTUB_STOP_WATCH_ACCESS = 5,
  GDBSTUB_STOP_EXITED = 6,
} gdbstub_stop_kind;

typedef enum gdbstub_resume_action {
  GDBSTUB_RESUME_CONT = 0,
  GDBSTUB_RESUME_STEP = 1,
} gdbstub_resume_action;

typedef enum gdbstub_target_status {
  GDBSTUB_TARGET_OK = 0,
  GDBSTUB_TARGET_FAULT = 1,
  GDBSTUB_TARGET_INVALID = 2,
  GDBSTUB_TARGET_UNSUPPORTED = 3,
} gdbstub_target_status;

typedef enum gdbstub_resume_state {
  GDBSTUB_RESUME_STOPPED = 0,
  GDBSTUB_RESUME_RUNNING = 1,
  GDBSTUB_RESUME_EXITED = 2,
} gdbstub_resume_state;

enum gdbstub_mem_perm {
  GDBSTUB_MEM_PERM_NONE = 0,
  GDBSTUB_MEM_PERM_READ = 1,
  GDBSTUB_MEM_PERM_WRITE = 2,
  GDBSTUB_MEM_PERM_EXEC = 4,
};

typedef enum gdbstub_breakpoint_type {
  GDBSTUB_BREAKPOINT_SOFTWARE = 0,
  GDBSTUB_BREAKPOINT_HARDWARE = 1,
  GDBSTUB_BREAKPOINT_WATCH_WRITE = 2,
  GDBSTUB_BREAKPOINT_WATCH_READ = 3,
  GDBSTUB_BREAKPOINT_WATCH_ACCESS = 4,
} gdbstub_breakpoint_type;

typedef struct gdbstub_stop_reason {
  gdbstub_stop_kind kind;
  int signal;
  uint64_t addr;
  int exit_code;
  uint8_t has_thread_id;
  uint64_t thread_id;
} gdbstub_stop_reason;

typedef struct gdbstub_resume_request {
  gdbstub_resume_action action;
  uint8_t has_addr;
  uint64_t addr;
  uint8_t has_signal;
  int signal;
} gdbstub_resume_request;

typedef struct gdbstub_resume_result {
  gdbstub_resume_state state;
  gdbstub_stop_reason stop;
  int exit_code;
} gdbstub_resume_result;

typedef struct gdbstub_breakpoint_spec {
  gdbstub_breakpoint_type type;
  uint64_t addr;
  uint32_t length;
} gdbstub_breakpoint_spec;

typedef struct gdbstub_memory_region {
  uint64_t start;
  uint64_t size;
  uint8_t perms;
  uint8_t has_name;
  gdbstub_string_view name;
  gdbstub_slice_string types;
} gdbstub_memory_region;

typedef struct gdbstub_memory_region_info {
  uint64_t start;
  uint64_t size;
  uint8_t mapped;
  uint8_t perms;
  uint8_t has_name;
  gdbstub_string_view name;
  gdbstub_slice_string types;
} gdbstub_memory_region_info;

typedef struct gdbstub_host_info {
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
} gdbstub_host_info;

typedef struct gdbstub_process_info {
  int pid;
  gdbstub_string_view triple;
  gdbstub_string_view endian;
  int ptr_size;
  gdbstub_string_view ostype;
} gdbstub_process_info;

typedef struct gdbstub_shlib_info {
  uint8_t has_info_addr;
  uint64_t info_addr;
} gdbstub_shlib_info;

typedef struct gdbstub_register_info {
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
} gdbstub_register_info;

typedef struct gdbstub_arch_spec {
  gdbstub_string_view target_xml;
  gdbstub_string_view xml_arch_name;
  gdbstub_string_view osabi;
  int reg_count;
  int pc_reg_num;
  uint8_t has_address_bits;
  int address_bits;
  uint8_t swap_register_endianness;
} gdbstub_arch_spec;

typedef void (*gdbstub_stop_notify_fn)(void* ctx, const gdbstub_stop_reason* reason);

typedef struct gdbstub_stop_notifier {
  void* ctx;
  gdbstub_stop_notify_fn notify;
} gdbstub_stop_notifier;

typedef size_t (*gdbstub_reg_size_fn)(void* ctx, int regno);
typedef gdbstub_target_status (*gdbstub_read_reg_fn)(void* ctx, int regno, uint8_t* out, size_t out_len);
typedef gdbstub_target_status (*gdbstub_write_reg_fn)(
    void* ctx,
    int regno,
    const uint8_t* data,
    size_t data_len
);

typedef gdbstub_target_status (*gdbstub_read_mem_fn)(void* ctx, uint64_t addr, uint8_t* out, size_t out_len);
typedef gdbstub_target_status (*gdbstub_write_mem_fn)(
    void* ctx,
    uint64_t addr,
    const uint8_t* data,
    size_t data_len
);

typedef gdbstub_resume_result (*gdbstub_resume_fn)(void* ctx, const gdbstub_resume_request* request);
typedef void (*gdbstub_interrupt_fn)(void* ctx);
typedef uint8_t (*gdbstub_poll_stop_fn)(void* ctx, gdbstub_stop_reason* out);
typedef void (*gdbstub_set_stop_notifier_fn)(void* ctx, gdbstub_stop_notifier notifier);

typedef gdbstub_target_status (*gdbstub_breakpoint_fn)(void* ctx, const gdbstub_breakpoint_spec* spec);

typedef uint8_t (*gdbstub_region_info_fn)(
    void* ctx,
    uint64_t addr,
    gdbstub_memory_region_info* out
);

typedef gdbstub_slice_region (*gdbstub_memory_map_fn)(void* ctx);

typedef gdbstub_slice_u64 (*gdbstub_thread_ids_fn)(void* ctx);
typedef uint64_t (*gdbstub_current_thread_fn)(void* ctx);
typedef gdbstub_target_status (*gdbstub_set_current_thread_fn)(void* ctx, uint64_t tid);
typedef uint8_t (*gdbstub_thread_pc_fn)(void* ctx, uint64_t tid, uint64_t* out);
typedef uint8_t (*gdbstub_thread_name_fn)(void* ctx, uint64_t tid, gdbstub_string_view* out);
typedef uint8_t (*gdbstub_thread_stop_reason_fn)(void* ctx, uint64_t tid, gdbstub_stop_reason* out);

typedef uint8_t (*gdbstub_get_host_info_fn)(void* ctx, gdbstub_host_info* out);
typedef uint8_t (*gdbstub_get_process_info_fn)(void* ctx, gdbstub_process_info* out);
typedef uint8_t (*gdbstub_get_shlib_info_fn)(void* ctx, gdbstub_shlib_info* out);
typedef uint8_t (*gdbstub_get_register_info_fn)(void* ctx, int regno, gdbstub_register_info* out);

typedef struct gdbstub_regs_iface {
  void* ctx;
  gdbstub_reg_size_fn reg_size;
  gdbstub_read_reg_fn read_reg;
  gdbstub_write_reg_fn write_reg;
} gdbstub_regs_iface;

typedef struct gdbstub_mem_iface {
  void* ctx;
  gdbstub_read_mem_fn read_mem;
  gdbstub_write_mem_fn write_mem;
} gdbstub_mem_iface;

typedef struct gdbstub_run_iface {
  void* ctx;
  gdbstub_resume_fn resume;
  gdbstub_interrupt_fn interrupt;
  gdbstub_poll_stop_fn poll_stop;
  gdbstub_set_stop_notifier_fn set_stop_notifier;
} gdbstub_run_iface;

typedef struct gdbstub_breakpoints_iface {
  void* ctx;
  gdbstub_breakpoint_fn set_breakpoint;
  gdbstub_breakpoint_fn remove_breakpoint;
} gdbstub_breakpoints_iface;

typedef struct gdbstub_memory_layout_iface {
  void* ctx;
  gdbstub_region_info_fn region_info;
  gdbstub_memory_map_fn memory_map;
} gdbstub_memory_layout_iface;

typedef struct gdbstub_threads_iface {
  void* ctx;
  gdbstub_thread_ids_fn thread_ids;
  gdbstub_current_thread_fn current_thread;
  gdbstub_set_current_thread_fn set_current_thread;
  gdbstub_thread_pc_fn thread_pc;
  gdbstub_thread_name_fn thread_name;
  gdbstub_thread_stop_reason_fn thread_stop_reason;
} gdbstub_threads_iface;

typedef struct gdbstub_host_info_iface {
  void* ctx;
  gdbstub_get_host_info_fn get_host_info;
} gdbstub_host_info_iface;

typedef struct gdbstub_process_info_iface {
  void* ctx;
  gdbstub_get_process_info_fn get_process_info;
} gdbstub_process_info_iface;

typedef struct gdbstub_shlib_info_iface {
  void* ctx;
  gdbstub_get_shlib_info_fn get_shlib_info;
} gdbstub_shlib_info_iface;

typedef struct gdbstub_register_info_iface {
  void* ctx;
  gdbstub_get_register_info_fn get_register_info;
} gdbstub_register_info_iface;

typedef struct gdbstub_target_config {
  gdbstub_regs_iface regs;
  gdbstub_mem_iface mem;
  gdbstub_run_iface run;
  const gdbstub_breakpoints_iface* breakpoints;
  const gdbstub_memory_layout_iface* memory_layout;
  const gdbstub_threads_iface* threads;
  const gdbstub_host_info_iface* host;
  const gdbstub_process_info_iface* process;
  const gdbstub_shlib_info_iface* shlib;
  const gdbstub_register_info_iface* reg_info;
} gdbstub_target_config;

typedef struct gdbstub_target gdbstub_target;
typedef struct gdbstub_transport gdbstub_transport;
typedef struct gdbstub_server gdbstub_server;

gdbstub_string_view gdbstub_version(void);

gdbstub_transport* gdbstub_transport_tcp_create(void);
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
void gdbstub_server_notify_stop(gdbstub_server* server, const gdbstub_stop_reason* reason);
void gdbstub_server_stop(gdbstub_server* server);

#ifdef __cplusplus
}
#endif
