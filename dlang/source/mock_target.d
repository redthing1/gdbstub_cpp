/**
 * MockTarget - A perfectly obedient, observable state machine for a RISC-V32 target.
 * This target is designed to be predictable and easy to test against.
 *
 * Features:
 * - 33 registers (32 general purpose + PC)
 * - Simple memory model with read/write tracking
 * - Breakpoint support with hit tracking
 * - Deterministic execution model
 */
module mock_target;

import gdbstub;
import std.typecons : Nullable, nullable;
import core.stdc.string : memcpy;

/**
 * MockTarget - A perfectly obedient, observable state machine for a RISC-V32 target.
 * This target is designed to be predictable and easy to test against.
 *
 * Features:
 * - 33 registers (32 general purpose + PC)
 * - Simple memory model with read/write tracking
 * - Breakpoint support with hit tracking
 * - Deterministic execution model
 */
struct MockTarget {
    // RISC-V32 has 32 general purpose registers + PC
    enum int NUM_REGS = 33;
    enum int PC_REG = 32;
    enum size_t REG_SIZE = 4; // 32-bit registers

    // --- GDB Target Description XML for RISC-V 32-bit ---
    // This is the modern, standard way to describe the target's registers.
    // It is required for full compatibility with GDB and LLDB, especially for writable registers.
    enum string riscv32_target_xml =
        `<?xml version="1.0"?>` ~
        `<!DOCTYPE target SYSTEM "gdb-target.dtd">` ~
        `<target version="1.0">` ~
        `  <architecture>riscv:rv32</architecture>` ~
        `  <feature name="org.gnu.gdb.riscv.cpu">` ~
        `    <reg name="x0" bitsize="32" regnum="0" type="int32" altname="zero"/>` ~
        `    <reg name="x1" bitsize="32" regnum="1" type="code_ptr" altname="ra"/>` ~
        `    <reg name="x2" bitsize="32" regnum="2" type="data_ptr" altname="sp"/>` ~
        `    <reg name="x3" bitsize="32" regnum="3" type="data_ptr" altname="gp"/>` ~
        `    <reg name="x4" bitsize="32" regnum="4" type="data_ptr" altname="tp"/>` ~
        `    <reg name="x5" bitsize="32" regnum="5" type="int32" altname="t0"/>` ~
        `    <reg name="x6" bitsize="32" regnum="6" type="int32" altname="t1"/>` ~
        `    <reg name="x7" bitsize="32" regnum="7" type="int32" altname="t2"/>` ~
        `    <reg name="x8" bitsize="32" regnum="8" type="int32" altname="s0"/>` ~
        `    <reg name="x9" bitsize="32" regnum="9" type="int32" altname="s1"/>` ~
        `    <reg name="x10" bitsize="32" regnum="10" type="int32" altname="a0"/>` ~
        `    <reg name="x11" bitsize="32" regnum="11" type="int32" altname="a1"/>` ~
        `    <reg name="x12" bitsize="32" regnum="12" type="int32" altname="a2"/>` ~
        `    <reg name="x13" bitsize="32" regnum="13" type="int32" altname="a3"/>` ~
        `    <reg name="x14" bitsize="32" regnum="14" type="int32" altname="a4"/>` ~
        `    <reg name="x15" bitsize="32" regnum="15" type="int32" altname="a5"/>` ~
        `    <reg name="x16" bitsize="32" regnum="16" type="int32" altname="a6"/>` ~
        `    <reg name="x17" bitsize="32" regnum="17" type="int32" altname="a7"/>` ~
        `    <reg name="x18" bitsize="32" regnum="18" type="int32" altname="s2"/>` ~
        `    <reg name="x19" bitsize="32" regnum="19" type="int32" altname="s3"/>` ~
        `    <reg name="x20" bitsize="32" regnum="20" type="int32" altname="s4"/>` ~
        `    <reg name="x21" bitsize="32" regnum="21" type="int32" altname="s5"/>` ~
        `    <reg name="x22" bitsize="32" regnum="22" type="int32" altname="s6"/>` ~
        `    <reg name="x23" bitsize="32" regnum="23" type="int32" altname="s7"/>` ~
        `    <reg name="x24" bitsize="32" regnum="24" type="int32" altname="s8"/>` ~
        `    <reg name="x25" bitsize="32" regnum="25" type="int32" altname="s9"/>` ~
        `    <reg name="x26" bitsize="32" regnum="26" type="int32" altname="s10"/>` ~
        `    <reg name="x27" bitsize="32" regnum="27" type="int32" altname="s11"/>` ~
        `    <reg name="x28" bitsize="32" regnum="28" type="int32" altname="t3"/>` ~
        `    <reg name="x29" bitsize="32" regnum="29" type="int32" altname="t4"/>` ~
        `    <reg name="x30" bitsize="32" regnum="30" type="int32" altname="t5"/>` ~
        `    <reg name="x31" bitsize="32" regnum="31" type="int32" altname="t6"/>` ~
        `    <reg name="pc" bitsize="32" regnum="32" type="code_ptr"/>` ~
        `  </feature>` ~
        `</target>`;

    // Register storage (x0-x31 + PC)
    uint[NUM_REGS] regs;

    // Memory storage (simple flat model)
    ubyte[uint] memory;

    // Breakpoint storage
    breakpoint_type[uint] breakpoints;

    // Execution state
    bool running = false;
    bool hit_breakpoint = false;
    uint breakpoint_addr = 0;

    // CPU/Thread state (for SMP support)
    int current_cpu = 0;

    void reset() {
        regs[] = 0;
        regs[PC_REG] = 0x80000000; // Default PC
        memory.clear();
        breakpoints.clear();
        running = false;
        hit_breakpoint = false;
        breakpoint_addr = 0;
    }

    // Required GDB stub interface methods

    /**
     * Continue execution until breakpoint or manual stop
     */
    Nullable!stop_reason cont() {
        running = true;
        hit_breakpoint = false;

        // Simulate simple execution: check for breakpoint at current PC
        uint pc = regs[PC_REG];
        auto bp_ptr = pc in breakpoints;
        if (bp_ptr !is null) {
            hit_breakpoint = true;
            breakpoint_addr = pc;
            running = false;
            return nullable(stop_reason(stop_type.sw_break, gdb_signal.TRAP, pc));
        }

        // If no breakpoint, just stop immediately for testing
        // In a real target, this would execute until a break condition
        running = false;
        return nullable(stop_reason(stop_type.signal, gdb_signal.TRAP));
    }

    /**
     * Single step execution
     */
    Nullable!stop_reason stepi() {
        // Increment PC by 4 (instruction size)
        regs[PC_REG] += 4;

        // Check for breakpoint at new PC
        uint pc = regs[PC_REG];
        auto bp_ptr = pc in breakpoints;
        if (bp_ptr !is null) {
            hit_breakpoint = true;
            breakpoint_addr = pc;
            return nullable(stop_reason(stop_type.sw_break, gdb_signal.TRAP, pc));
        }

        return nullable(stop_reason(stop_type.signal, gdb_signal.TRAP));
    }

    /**
     * Get register size in bytes
     */
    size_t reg_size(int regno) const {
        if (regno < 0 || regno >= NUM_REGS) {
            return 0;
        }
        return REG_SIZE;
    }

    /**
     * Read register value
     */
    int read_reg(int regno, ubyte[] data) {
        if (regno < 0 || regno >= NUM_REGS || data.length < REG_SIZE) {
            return -1;
        }

        // Special handling for x0 (always zero in RISC-V)
        if (regno == 0) {
            uint zero = 0;
            memcpy(data.ptr, &zero, REG_SIZE);
        } else {
            memcpy(data.ptr, &regs[regno], REG_SIZE);
        }

        return 0;
    }

    /**
     * Write register value
     */
    int write_reg(int regno, const(ubyte)[] data) {
        if (regno < 0 || regno >= NUM_REGS || data.length < REG_SIZE) {
            return -1;
        }

        // x0 is hardwired to zero in RISC-V, ignore writes
        if (regno == 0) {
            return 0;
        }

        memcpy(&regs[regno], data.ptr, REG_SIZE);
        return 0;
    }

    /**
     * Read memory
     */
    int read_mem(size_t addr, size_t len, ubyte[] data) {
        if (data.length < len || len == 0) {
            return -1;
        }

        for (size_t i = 0; i < len; ++i) {
            uint mem_addr = cast(uint)(addr + i);
            auto mem_ptr = mem_addr in memory;
            if (mem_ptr !is null) {
                data[i] = *mem_ptr;
            } else {
                // Uninitialized memory reads as zero
                data[i] = 0;
            }
        }

        return 0;
    }

    /**
     * Write memory
     */
    int write_mem(size_t addr, size_t len, const(ubyte)[] data) {
        if (data.length < len || len == 0) {
            return -1;
        }

        for (size_t i = 0; i < len; ++i) {
            memory[cast(uint)(addr + i)] = data[i];
        }

        return 0;
    }

    /**
     * Set breakpoint
     */
    bool set_breakpoint(size_t addr, breakpoint_type type) {
        breakpoints[cast(uint)addr] = type;
        return true;
    }

    /**
     * Delete breakpoint
     */
    bool del_breakpoint(size_t addr, breakpoint_type type) {
        uint bp_addr = cast(uint)addr;
        auto bp_ptr = bp_addr in breakpoints;
        if (bp_ptr !is null && *bp_ptr == type) {
            breakpoints.remove(bp_addr);
            return true;
        }
        return false;
    }

    /**
     * Get memory region info
     */
    Nullable!mem_region get_mem_region_info(size_t addr) {
        // Simple memory layout:
        // 0x80000000-0x8FFFFFFF: RAM (readable, writable, executable)
        // 0x10000000-0x1000FFFF: I/O (readable, writable)
        // Everything else: unmapped

        if (addr >= 0x80000000 && addr <= 0x8FFFFFFF) {
            return nullable(mem_region(0x80000000, 0x10000000, "rwx"));
        } else if (addr >= 0x10000000 && addr <= 0x1000FFFF) {
            return nullable(mem_region(0x10000000, 0x10000, "rw"));
        }

        return Nullable!mem_region.init;
    }

    /**
     * Get process info - required for LLDB compatibility
     */
    Nullable!process_info get_process_info() {
        return nullable(process_info(1, "riscv32-unknown-elf", "little", "bare", 4));
    }

    /**
     * Get host info - provides information about the host system for LLDB
     */
    Nullable!host_info get_host_info() {
        return nullable(host_info(
            "riscv32-unknown-elf",
            "little",
            4,
            "mock-target",
            "1.0.0",
            "mock-build-001",
            "mock-kernel"
        ));
    }

    /**
     * Handle interrupt
     */
    void on_interrupt() { running = false; }

    /**
     * Get current CPU/thread ID (required for thread support)
     */
    int get_cpu() const { return current_cpu; }

    /**
     * Set current CPU/thread ID (required for thread support)
     */
    void set_cpu(int cpu_id) {
        if (cpu_id >= 0 && cpu_id < 1) { // We only have 1 CPU for now
            current_cpu = cpu_id;
        }
    }

    // Test helper methods

    /**
     * Check if breakpoint was hit
     */
    bool was_breakpoint_hit() const { return hit_breakpoint; }

    /**
     * Get the address of the last hit breakpoint
     */
    uint get_breakpoint_addr() const { return breakpoint_addr; }

    /**
     * Get current PC value
     */
    uint get_pc() const { return regs[PC_REG]; }

    /**
     * Set PC value
     */
    void set_pc(uint pc) { regs[PC_REG] = pc; }

    /**
     * Check if breakpoint exists at address
     */
    bool has_breakpoint(uint addr) const { return (addr in breakpoints) !is null; }

    /**
     * Get number of breakpoints
     */
    size_t get_breakpoint_count() const { return breakpoints.length; }
}