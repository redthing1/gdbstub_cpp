module gdbstub_cpp;

import core.stdc.stdint : uint32_t, uint64_t, uint8_t;
import std.exception : enforce;
import std.typecons : Nullable, nullable;
import gdbstub_cpp_c_api;

public enum StopKind : int {
    signal = gdbstub_stop_kind.GDBSTUB_STOP_SIGNAL,
    swBreak = gdbstub_stop_kind.GDBSTUB_STOP_SW_BREAK,
    hwBreak = gdbstub_stop_kind.GDBSTUB_STOP_HW_BREAK,
    watchRead = gdbstub_stop_kind.GDBSTUB_STOP_WATCH_READ,
    watchWrite = gdbstub_stop_kind.GDBSTUB_STOP_WATCH_WRITE,
    watchAccess = gdbstub_stop_kind.GDBSTUB_STOP_WATCH_ACCESS,
    exited = gdbstub_stop_kind.GDBSTUB_STOP_EXITED,
}

public enum ReplayLogBoundary : int {
    begin = gdbstub_replay_log_boundary.GDBSTUB_REPLAY_LOG_BEGIN,
    end = gdbstub_replay_log_boundary.GDBSTUB_REPLAY_LOG_END,
}

public enum ResumeDirection : int {
    forward = gdbstub_resume_direction.GDBSTUB_RESUME_FORWARD,
    reverse = gdbstub_resume_direction.GDBSTUB_RESUME_REVERSE,
}

public enum ResumeAction : int {
    cont = gdbstub_resume_action.GDBSTUB_RESUME_CONT,
    step = gdbstub_resume_action.GDBSTUB_RESUME_STEP,
    rangeStep = gdbstub_resume_action.GDBSTUB_RESUME_RANGE_STEP,
}

public enum ResumeState : int {
    stopped = gdbstub_resume_state.GDBSTUB_RESUME_STOPPED,
    running = gdbstub_resume_state.GDBSTUB_RESUME_RUNNING,
    exited = gdbstub_resume_state.GDBSTUB_RESUME_EXITED,
}

public enum TargetStatus : int {
    ok = gdbstub_target_status.GDBSTUB_TARGET_OK,
    fault = gdbstub_target_status.GDBSTUB_TARGET_FAULT,
    invalid = gdbstub_target_status.GDBSTUB_TARGET_INVALID,
    unsupported = gdbstub_target_status.GDBSTUB_TARGET_UNSUPPORTED,
}

public enum MemPerm : uint8_t {
    none = gdbstub_mem_perm.GDBSTUB_MEM_PERM_NONE,
    read = gdbstub_mem_perm.GDBSTUB_MEM_PERM_READ,
    write = gdbstub_mem_perm.GDBSTUB_MEM_PERM_WRITE,
    exec = gdbstub_mem_perm.GDBSTUB_MEM_PERM_EXEC,
}
public bool hasPerm(MemPerm value, MemPerm flag) {
    return (cast(uint8_t)value & cast(uint8_t)flag) != 0;
}

public enum BreakpointType : int {
    software = gdbstub_breakpoint_type.GDBSTUB_BREAKPOINT_SOFTWARE,
    hardware = gdbstub_breakpoint_type.GDBSTUB_BREAKPOINT_HARDWARE,
    watchWrite = gdbstub_breakpoint_type.GDBSTUB_BREAKPOINT_WATCH_WRITE,
    watchRead = gdbstub_breakpoint_type.GDBSTUB_BREAKPOINT_WATCH_READ,
    watchAccess = gdbstub_breakpoint_type.GDBSTUB_BREAKPOINT_WATCH_ACCESS,
}

public struct StopReason {
    StopKind kind = StopKind.signal;
    int signal = 0;
    ulong addr = 0;
    int exitCode = 0;
    Nullable!ulong threadId;
    Nullable!ReplayLogBoundary replayLog;
}

public struct AddressRange {
    ulong start = 0;
    ulong end = 0;
}

public struct ResumeRequest {
    ResumeAction action = ResumeAction.cont;
    ResumeDirection direction = ResumeDirection.forward;
    Nullable!ulong addr;
    Nullable!int signal;
    Nullable!AddressRange range;
}

public struct ResumeResult {
    ResumeState state = ResumeState.stopped;
    StopReason stop;
    int exitCode = 0;
    TargetStatus status = TargetStatus.ok;
}

public struct RunCapabilities {
    bool reverseContinue = false;
    bool reverseStep = false;
    bool rangeStep = false;
    bool nonStop = false;
}

public struct BreakpointCapabilities {
    bool software = false;
    bool hardware = false;
    bool watchRead = false;
    bool watchWrite = false;
    bool watchAccess = false;
}

public struct BreakpointSpec {
    BreakpointType type = BreakpointType.software;
    ulong addr = 0;
    uint length = 0;
}

public struct MemoryRegion {
    ulong start = 0;
    ulong size = 0;
    MemPerm perms = MemPerm.none;
    Nullable!string name;
    string[] types;
}

public struct MemoryRegionInfo {
    ulong start = 0;
    ulong size = 0;
    bool mapped = false;
    MemPerm perms = MemPerm.none;
    Nullable!string name;
    string[] types;
}

public struct HostInfo {
    string triple = "unknown-unknown-unknown";
    string endian = "little";
    int ptrSize = 0;
    string hostname = "gdbstub";
    Nullable!string osVersion;
    Nullable!string osBuild;
    Nullable!string osKernel;
    Nullable!int addressingBits;
}

public struct ProcessInfo {
    int pid = 0;
    string triple = "unknown-unknown-unknown";
    string endian = "little";
    int ptrSize = 0;
    string ostype = "unknown";
}

public struct ShlibInfo {
    Nullable!ulong infoAddr;
}

public struct RegisterInfo {
    string name;
    Nullable!string altName;
    int bitsize = 0;
    Nullable!size_t offset;
    string encoding = "";
    string format = "";
    Nullable!string set;
    Nullable!int gccRegnum;
    Nullable!int dwarfRegnum;
    Nullable!string generic;
    int[] containerRegs;
    int[] invalidateRegs;
}

public struct ArchSpec {
    string targetXml;
    string xmlArchName;
    string osabi;
    int regCount = 0;
    int pcRegNum = -1;
    Nullable!int addressBits;
    bool swapRegisterEndianness = false;
}

public struct StopNotifier {
    private gdbstub_stop_notifier raw;

    bool isValid() const {
        return raw.notify !is null;
    }

    void notify(StopReason reason) {
        if (raw.notify is null) {
            return;
        }
        auto cReason = toCStopReason(reason);
        raw.notify(raw.ctx, &cReason);
    }
}

public struct RegsCallbacks {
    size_t delegate(int regno) regSize;
    TargetStatus delegate(int regno, ubyte[] buffer) readReg;
    TargetStatus delegate(int regno, const(ubyte)[] data) writeReg;
}

public struct MemCallbacks {
    TargetStatus delegate(ulong addr, ubyte[] buffer) readMem;
    TargetStatus delegate(ulong addr, const(ubyte)[] data) writeMem;
}

public struct RunCallbacks {
    ResumeResult delegate(ResumeRequest request) resume;
    void delegate() interrupt;
    Nullable!StopReason delegate() pollStop;
    void delegate(StopNotifier notifier) setStopNotifier;
    Nullable!RunCapabilities delegate() getCapabilities;
}

public struct BreakpointsCallbacks {
    TargetStatus delegate(BreakpointSpec spec) setBreakpoint;
    TargetStatus delegate(BreakpointSpec spec) removeBreakpoint;
    Nullable!BreakpointCapabilities delegate() getCapabilities;
}

public struct MemoryLayoutCallbacks {
    Nullable!MemoryRegionInfo delegate(ulong addr) regionInfo;
    MemoryRegion[] delegate() memoryMap;
}

public struct ThreadsCallbacks {
    ulong[] delegate() threadIds;
    ulong delegate() currentThread;
    TargetStatus delegate(ulong tid) setCurrentThread;
    Nullable!ulong delegate(ulong tid) threadPc;
    Nullable!string delegate(ulong tid) threadName;
    Nullable!StopReason delegate(ulong tid) threadStopReason;
}

public struct HostInfoCallbacks {
    Nullable!HostInfo delegate() getHostInfo;
}

public struct ProcessInfoCallbacks {
    Nullable!ProcessInfo delegate() getProcessInfo;
}

public struct ShlibInfoCallbacks {
    Nullable!ShlibInfo delegate() getShlibInfo;
}

public struct RegisterInfoCallbacks {
    Nullable!RegisterInfo delegate(int regno) getRegisterInfo;
}

public struct TargetCallbacks {
    RegsCallbacks regs;
    MemCallbacks mem;
    RunCallbacks run;
    BreakpointsCallbacks breakpoints;
    MemoryLayoutCallbacks memoryLayout;
    ThreadsCallbacks threads;
    HostInfoCallbacks host;
    ProcessInfoCallbacks process;
    ShlibInfoCallbacks shlib;
    RegisterInfoCallbacks registerInfo;
}

public struct TargetBuilder {
    private TargetCallbacks callbacks;

    ref TargetBuilder withRegs(RegsCallbacks regs) {
        callbacks.regs = regs;
        return this;
    }

    ref TargetBuilder withRegs(
        size_t delegate(int regno) regSize,
        TargetStatus delegate(int regno, ubyte[] buffer) readReg,
        TargetStatus delegate(int regno, const(ubyte)[] data) writeReg
    ) {
        RegsCallbacks regs;
        regs.regSize = regSize;
        regs.readReg = readReg;
        regs.writeReg = writeReg;
        callbacks.regs = regs;
        return this;
    }

    ref TargetBuilder withMem(MemCallbacks mem) {
        callbacks.mem = mem;
        return this;
    }

    ref TargetBuilder withMem(
        TargetStatus delegate(ulong addr, ubyte[] buffer) readMem,
        TargetStatus delegate(ulong addr, const(ubyte)[] data) writeMem
    ) {
        MemCallbacks mem;
        mem.readMem = readMem;
        mem.writeMem = writeMem;
        callbacks.mem = mem;
        return this;
    }

    ref TargetBuilder withRun(RunCallbacks run) {
        callbacks.run = run;
        return this;
    }

    ref TargetBuilder withRun(
        ResumeResult delegate(ResumeRequest request) resume,
        void delegate() interrupt = null,
        Nullable!StopReason delegate() pollStop = null,
        void delegate(StopNotifier notifier) setStopNotifier = null,
        Nullable!RunCapabilities delegate() getCapabilities = null
    ) {
        RunCallbacks run;
        run.resume = resume;
        run.interrupt = interrupt;
        run.pollStop = pollStop;
        run.setStopNotifier = setStopNotifier;
        run.getCapabilities = getCapabilities;
        callbacks.run = run;
        return this;
    }

    ref TargetBuilder withBreakpoints(BreakpointsCallbacks breakpoints) {
        callbacks.breakpoints = breakpoints;
        return this;
    }

    ref TargetBuilder withBreakpoints(
        TargetStatus delegate(BreakpointSpec spec) setBreakpoint,
        TargetStatus delegate(BreakpointSpec spec) removeBreakpoint,
        Nullable!BreakpointCapabilities delegate() getCapabilities = null
    ) {
        BreakpointsCallbacks breakpoints;
        breakpoints.setBreakpoint = setBreakpoint;
        breakpoints.removeBreakpoint = removeBreakpoint;
        breakpoints.getCapabilities = getCapabilities;
        callbacks.breakpoints = breakpoints;
        return this;
    }

    ref TargetBuilder withMemoryLayout(MemoryLayoutCallbacks layout) {
        callbacks.memoryLayout = layout;
        return this;
    }

    ref TargetBuilder withMemoryLayout(
        Nullable!MemoryRegionInfo delegate(ulong addr) regionInfo,
        MemoryRegion[] delegate() memoryMap
    ) {
        MemoryLayoutCallbacks layout;
        layout.regionInfo = regionInfo;
        layout.memoryMap = memoryMap;
        callbacks.memoryLayout = layout;
        return this;
    }

    ref TargetBuilder withThreads(ThreadsCallbacks threads) {
        callbacks.threads = threads;
        return this;
    }

    ref TargetBuilder withThreads(
        ulong[] delegate() threadIds,
        ulong delegate() currentThread,
        TargetStatus delegate(ulong tid) setCurrentThread,
        Nullable!ulong delegate(ulong tid) threadPc,
        Nullable!string delegate(ulong tid) threadName,
        Nullable!StopReason delegate(ulong tid) threadStopReason
    ) {
        ThreadsCallbacks threads;
        threads.threadIds = threadIds;
        threads.currentThread = currentThread;
        threads.setCurrentThread = setCurrentThread;
        threads.threadPc = threadPc;
        threads.threadName = threadName;
        threads.threadStopReason = threadStopReason;
        callbacks.threads = threads;
        return this;
    }

    ref TargetBuilder withHostInfo(HostInfoCallbacks host) {
        callbacks.host = host;
        return this;
    }

    ref TargetBuilder withHostInfo(Nullable!HostInfo delegate() getHostInfo) {
        HostInfoCallbacks host;
        host.getHostInfo = getHostInfo;
        callbacks.host = host;
        return this;
    }

    ref TargetBuilder withProcessInfo(ProcessInfoCallbacks process) {
        callbacks.process = process;
        return this;
    }

    ref TargetBuilder withProcessInfo(Nullable!ProcessInfo delegate() getProcessInfo) {
        ProcessInfoCallbacks process;
        process.getProcessInfo = getProcessInfo;
        callbacks.process = process;
        return this;
    }

    ref TargetBuilder withShlibInfo(ShlibInfoCallbacks shlib) {
        callbacks.shlib = shlib;
        return this;
    }

    ref TargetBuilder withShlibInfo(Nullable!ShlibInfo delegate() getShlibInfo) {
        ShlibInfoCallbacks shlib;
        shlib.getShlibInfo = getShlibInfo;
        callbacks.shlib = shlib;
        return this;
    }

    ref TargetBuilder withRegisterInfo(RegisterInfoCallbacks regInfo) {
        callbacks.registerInfo = regInfo;
        return this;
    }

    ref TargetBuilder withRegisterInfo(Nullable!RegisterInfo delegate(int regno) getRegisterInfo) {
        RegisterInfoCallbacks regInfo;
        regInfo.getRegisterInfo = getRegisterInfo;
        callbacks.registerInfo = regInfo;
        return this;
    }

    Target build() {
        return new Target(callbacks);
    }
}

public string versionString() {
    auto view = gdbstub_version();
    if (view.data is null || view.size == 0) {
        return "";
    }
    return view.data[0 .. view.size].idup;
}

public class Transport {
    protected gdbstub_transport* handle;

    protected this(gdbstub_transport* handle) {
        this.handle = handle;
    }

    ~this() {
        if (handle !is null) {
            gdbstub_transport_destroy(handle);
        }
    }

    private gdbstub_transport* release() {
        auto tmp = handle;
        handle = null;
        return tmp;
    }
}

public final class TransportTcp : Transport {
    this() {
        super(gdbstub_transport_tcp_create());
        enforce(handle !is null, "failed to create TCP transport");
    }
}

public final class Target {
    private gdbstub_target* handle;
    private TargetContext ctx;

    this(TargetCallbacks callbacks) {
        enforce(callbacks.regs.regSize !is null, "regs.regSize required");
        enforce(callbacks.regs.readReg !is null, "regs.readReg required");
        enforce(callbacks.regs.writeReg !is null, "regs.writeReg required");
        enforce(callbacks.mem.readMem !is null, "mem.readMem required");
        enforce(callbacks.mem.writeMem !is null, "mem.writeMem required");
        enforce(callbacks.run.resume !is null, "run.resume required");

        ctx = new TargetContext(callbacks);

        gdbstub_regs_iface regsIface;
        regsIface.ctx = cast(void*)ctx;
        regsIface.reg_size = &regSizeTramp;
        regsIface.read_reg = &readRegTramp;
        regsIface.write_reg = &writeRegTramp;

        gdbstub_mem_iface memIface;
        memIface.ctx = cast(void*)ctx;
        memIface.read_mem = &readMemTramp;
        memIface.write_mem = &writeMemTramp;

        gdbstub_run_iface runIface;
        runIface.ctx = cast(void*)ctx;
        runIface.resume = &resumeTramp;
        runIface.interrupt = callbacks.run.interrupt is null ? null : &interruptTramp;
        runIface.poll_stop = callbacks.run.pollStop is null ? null : &pollStopTramp;
        runIface.set_stop_notifier = callbacks.run.setStopNotifier is null ? null : &setStopNotifierTramp;
        runIface.get_capabilities = callbacks.run.getCapabilities is null ? null : &getRunCapabilitiesTramp;

        gdbstub_target_config config;
        config.regs = regsIface;
        config.mem = memIface;
        config.run = runIface;
        config.breakpoints = null;
        config.memory_layout = null;
        config.threads = null;
        config.host = null;
        config.process = null;
        config.shlib = null;
        config.reg_info = null;

        gdbstub_breakpoints_iface breakpointsIface;
        if (callbacks.breakpoints.setBreakpoint !is null && callbacks.breakpoints.removeBreakpoint !is null) {
            breakpointsIface.ctx = cast(void*)ctx;
            breakpointsIface.set_breakpoint = &setBreakpointTramp;
            breakpointsIface.remove_breakpoint = &removeBreakpointTramp;
            breakpointsIface.get_capabilities =
                callbacks.breakpoints.getCapabilities is null ? null : &getBreakpointCapabilitiesTramp;
            config.breakpoints = &breakpointsIface;
        }

        gdbstub_memory_layout_iface layoutIface;
        if (callbacks.memoryLayout.regionInfo !is null || callbacks.memoryLayout.memoryMap !is null) {
            layoutIface.ctx = cast(void*)ctx;
            layoutIface.region_info = callbacks.memoryLayout.regionInfo is null ? null : &regionInfoTramp;
            layoutIface.memory_map = callbacks.memoryLayout.memoryMap is null ? null : &memoryMapTramp;
            config.memory_layout = &layoutIface;
        }

        gdbstub_threads_iface threadsIface;
        if (callbacks.threads.threadIds !is null &&
            callbacks.threads.currentThread !is null &&
            callbacks.threads.setCurrentThread !is null &&
            callbacks.threads.threadPc !is null &&
            callbacks.threads.threadName !is null &&
            callbacks.threads.threadStopReason !is null) {
            threadsIface.ctx = cast(void*)ctx;
            threadsIface.thread_ids = &threadIdsTramp;
            threadsIface.current_thread = &currentThreadTramp;
            threadsIface.set_current_thread = &setCurrentThreadTramp;
            threadsIface.thread_pc = &threadPcTramp;
            threadsIface.thread_name = &threadNameTramp;
            threadsIface.thread_stop_reason = &threadStopReasonTramp;
            config.threads = &threadsIface;
        }

        gdbstub_host_info_iface hostIface;
        if (callbacks.host.getHostInfo !is null) {
            hostIface.ctx = cast(void*)ctx;
            hostIface.get_host_info = &hostInfoTramp;
            config.host = &hostIface;
        }

        gdbstub_process_info_iface processIface;
        if (callbacks.process.getProcessInfo !is null) {
            processIface.ctx = cast(void*)ctx;
            processIface.get_process_info = &processInfoTramp;
            config.process = &processIface;
        }

        gdbstub_shlib_info_iface shlibIface;
        if (callbacks.shlib.getShlibInfo !is null) {
            shlibIface.ctx = cast(void*)ctx;
            shlibIface.get_shlib_info = &shlibInfoTramp;
            config.shlib = &shlibIface;
        }

        gdbstub_register_info_iface regInfoIface;
        if (callbacks.registerInfo.getRegisterInfo !is null) {
            regInfoIface.ctx = cast(void*)ctx;
            regInfoIface.get_register_info = &registerInfoTramp;
            config.reg_info = &regInfoIface;
        }

        handle = gdbstub_target_create(&config);
        enforce(handle !is null, "failed to create target");
    }

    ~this() {
        if (handle !is null) {
            gdbstub_target_destroy(handle);
        }
    }

    private gdbstub_target* raw() {
        return handle;
    }
}

public final class Server {
    private gdbstub_server* handle;
    private Target targetRef;
    private Transport transportRef;

    this(Target target, ArchSpec arch, Transport transport) {
        enforce(target !is null, "target required");
        enforce(transport !is null, "transport required");
        targetRef = target;
        transportRef = transport;
        auto cArch = toCArchSpec(arch);
        handle = gdbstub_server_create(target.raw(), cArch, transport.release());
        enforce(handle !is null, "failed to create server");
    }

    ~this() {
        if (handle !is null) {
            gdbstub_server_destroy(handle);
        }
    }

    bool listen(string address) {
        auto view = toStringView(address);
        return gdbstub_server_listen(handle, view) != 0;
    }

    bool waitForConnection() {
        return gdbstub_server_wait_for_connection(handle) != 0;
    }

    bool hasConnection() {
        return gdbstub_server_has_connection(handle) != 0;
    }

    void serveForever() {
        gdbstub_server_serve_forever(handle);
    }

    bool poll(ulong timeoutMs) {
        return gdbstub_server_poll(handle, timeoutMs) != 0;
    }

    void notifyStop(StopReason reason) {
        auto cReason = toCStopReason(reason);
        gdbstub_server_notify_stop(handle, &cReason);
    }

    void stop() {
        gdbstub_server_stop(handle);
    }
}

private class TargetContext {
    TargetCallbacks callbacks;

    uint64_t[] threadIdsCache;
    MemoryRegion[] memoryMapCache;
    gdbstub_memory_region[] memoryMapC;
    gdbstub_string_view[][] memoryMapTypes;
    MemoryRegionInfo regionInfoCache;

    Nullable!string threadNameCache;
    Nullable!StopReason threadStopReasonCache;
    Nullable!HostInfo hostInfoCache;
    Nullable!ProcessInfo processInfoCache;
    Nullable!ShlibInfo shlibInfoCache;
    Nullable!RegisterInfo registerInfoCache;

    this(TargetCallbacks callbacks) {
        this.callbacks = callbacks;
    }
}

private gdbstub_string_view toStringView(string value) {
    gdbstub_string_view view;
    view.data = value.ptr;
    view.size = value.length;
    return view;
}

private gdbstub_string_view toStringViewNullable(Nullable!string value) {
    if (value.isNull) {
        return gdbstub_string_view(null, 0);
    }
    return toStringView(value.get);
}

private gdbstub_stop_reason toCStopReason(StopReason reason) {
    gdbstub_stop_reason result;
    result.kind = cast(gdbstub_stop_kind)reason.kind;
    result.signal = reason.signal;
    result.addr = reason.addr;
    result.exit_code = reason.exitCode;
    result.has_thread_id = reason.threadId.isNull ? 0 : 1;
    result.thread_id = reason.threadId.isNull ? 0 : reason.threadId.get;
    result.has_replay_log = reason.replayLog.isNull ? 0 : 1;
    result.replay_log = reason.replayLog.isNull
        ? gdbstub_replay_log_boundary.GDBSTUB_REPLAY_LOG_BEGIN
        : cast(gdbstub_replay_log_boundary)reason.replayLog.get;
    return result;
}

private StopReason toDStopReason(const gdbstub_stop_reason* reason) {
    StopReason result;
    if (reason is null) {
        return result;
    }
    result.kind = cast(StopKind)reason.kind;
    result.signal = reason.signal;
    result.addr = reason.addr;
    result.exitCode = reason.exit_code;
    if (reason.has_thread_id != 0) {
        result.threadId = nullable(cast(ulong)reason.thread_id);
    }
    if (reason.has_replay_log != 0) {
        result.replayLog = nullable(cast(ReplayLogBoundary)reason.replay_log);
    }
    return result;
}

private ResumeRequest toDResumeRequest(const gdbstub_resume_request* request) {
    ResumeRequest result;
    if (request is null) {
        return result;
    }
    result.action = cast(ResumeAction)request.action;
    result.direction = cast(ResumeDirection)request.direction;
    if (request.has_addr != 0) {
        result.addr = nullable(cast(ulong)request.addr);
    }
    if (request.has_signal != 0) {
        result.signal = nullable(cast(int)request.signal);
    }
    if (request.has_range != 0) {
        AddressRange range;
        range.start = request.range.start;
        range.end = request.range.end;
        result.range = nullable(range);
    }
    return result;
}

private gdbstub_resume_result toCResumeResult(ResumeResult result) {
    gdbstub_resume_result value;
    value.state = cast(gdbstub_resume_state)result.state;
    value.stop = toCStopReason(result.stop);
    value.exit_code = result.exitCode;
    value.status = cast(gdbstub_target_status)result.status;
    return value;
}

private gdbstub_run_capabilities toCRunCapabilities(RunCapabilities caps) {
    gdbstub_run_capabilities result;
    result.reverse_continue = caps.reverseContinue ? 1 : 0;
    result.reverse_step = caps.reverseStep ? 1 : 0;
    result.range_step = caps.rangeStep ? 1 : 0;
    result.non_stop = caps.nonStop ? 1 : 0;
    return result;
}

private gdbstub_breakpoint_capabilities toCBreakpointCapabilities(BreakpointCapabilities caps) {
    gdbstub_breakpoint_capabilities result;
    result.software = caps.software ? 1 : 0;
    result.hardware = caps.hardware ? 1 : 0;
    result.watch_read = caps.watchRead ? 1 : 0;
    result.watch_write = caps.watchWrite ? 1 : 0;
    result.watch_access = caps.watchAccess ? 1 : 0;
    return result;
}

private gdbstub_memory_region_info toCMemoryRegionInfo(MemoryRegionInfo info, TargetContext ctx) {
    gdbstub_memory_region_info result;
    result.start = info.start;
    result.size = info.size;
    result.mapped = info.mapped ? 1 : 0;
    result.perms = cast(uint8_t)info.perms;
    if (info.name.isNull) {
        result.has_name = 0;
        result.name = gdbstub_string_view(null, 0);
    } else {
        result.has_name = 1;
        result.name = toStringView(info.name.get);
    }
    ctx.memoryMapTypes.length = 1;
    auto types = info.types;
    ctx.memoryMapTypes[0].length = types.length;
    for (size_t i = 0; i < types.length; ++i) {
        ctx.memoryMapTypes[0][i] = toStringView(types[i]);
    }
    result.types.data = ctx.memoryMapTypes[0].ptr;
    result.types.len = ctx.memoryMapTypes[0].length;
    return result;
}

private gdbstub_host_info toCHostInfo(HostInfo info) {
    gdbstub_host_info result;
    result.triple = toStringView(info.triple);
    result.endian = toStringView(info.endian);
    result.ptr_size = info.ptrSize;
    result.hostname = toStringView(info.hostname);
    result.has_os_version = info.osVersion.isNull ? 0 : 1;
    result.os_version = toStringViewNullable(info.osVersion);
    result.has_os_build = info.osBuild.isNull ? 0 : 1;
    result.os_build = toStringViewNullable(info.osBuild);
    result.has_os_kernel = info.osKernel.isNull ? 0 : 1;
    result.os_kernel = toStringViewNullable(info.osKernel);
    result.has_addressing_bits = info.addressingBits.isNull ? 0 : 1;
    result.addressing_bits = info.addressingBits.isNull ? 0 : info.addressingBits.get;
    return result;
}

private gdbstub_process_info toCProcessInfo(ProcessInfo info) {
    gdbstub_process_info result;
    result.pid = info.pid;
    result.triple = toStringView(info.triple);
    result.endian = toStringView(info.endian);
    result.ptr_size = info.ptrSize;
    result.ostype = toStringView(info.ostype);
    return result;
}

private gdbstub_shlib_info toCShlibInfo(ShlibInfo info) {
    gdbstub_shlib_info result;
    result.has_info_addr = info.infoAddr.isNull ? 0 : 1;
    result.info_addr = info.infoAddr.isNull ? 0 : info.infoAddr.get;
    return result;
}

private gdbstub_register_info toCRegisterInfo(RegisterInfo info, TargetContext ctx) {
    ctx.registerInfoCache = nullable(info);
    auto cache = ctx.registerInfoCache.get;
    gdbstub_register_info result;
    result.name = toStringView(cache.name);
    result.has_alt_name = cache.altName.isNull ? 0 : 1;
    result.alt_name = toStringViewNullable(cache.altName);
    result.bitsize = cache.bitsize;
    result.has_offset = cache.offset.isNull ? 0 : 1;
    result.offset = cache.offset.isNull ? 0 : cache.offset.get;
    result.encoding = toStringView(cache.encoding);
    result.format = toStringView(cache.format);
    result.has_set = cache.set.isNull ? 0 : 1;
    result.set = toStringViewNullable(cache.set);
    result.has_gcc_regnum = cache.gccRegnum.isNull ? 0 : 1;
    result.gcc_regnum = cache.gccRegnum.isNull ? 0 : cache.gccRegnum.get;
    result.has_dwarf_regnum = cache.dwarfRegnum.isNull ? 0 : 1;
    result.dwarf_regnum = cache.dwarfRegnum.isNull ? 0 : cache.dwarfRegnum.get;
    result.has_generic = cache.generic.isNull ? 0 : 1;
    result.generic = toStringViewNullable(cache.generic);
    result.container_regs.data = cache.containerRegs.ptr;
    result.container_regs.len = cache.containerRegs.length;
    result.invalidate_regs.data = cache.invalidateRegs.ptr;
    result.invalidate_regs.len = cache.invalidateRegs.length;
    return result;
}

private gdbstub_arch_spec toCArchSpec(ArchSpec spec) {
    gdbstub_arch_spec result;
    result.target_xml = toStringView(spec.targetXml);
    result.xml_arch_name = toStringView(spec.xmlArchName);
    result.osabi = toStringView(spec.osabi);
    result.reg_count = spec.regCount;
    result.pc_reg_num = spec.pcRegNum;
    result.has_address_bits = spec.addressBits.isNull ? 0 : 1;
    result.address_bits = spec.addressBits.isNull ? 0 : spec.addressBits.get;
    result.swap_register_endianness = spec.swapRegisterEndianness ? 1 : 0;
    return result;
}

private extern(C) size_t regSizeTramp(void* ctx, int regno) {
    auto c = cast(TargetContext)ctx;
    return c.callbacks.regs.regSize(regno);
}

private extern(C) gdbstub_target_status readRegTramp(void* ctx, int regno, uint8_t* buffer, size_t bufferLen) {
    auto c = cast(TargetContext)ctx;
    auto slice = buffer[0 .. bufferLen];
    auto status = c.callbacks.regs.readReg(regno, slice);
    return cast(gdbstub_target_status)status;
}

private extern(C) gdbstub_target_status writeRegTramp(
    void* ctx,
    int regno,
    const(uint8_t)* data,
    size_t dataLen
) {
    auto c = cast(TargetContext)ctx;
    auto slice = data[0 .. dataLen];
    auto status = c.callbacks.regs.writeReg(regno, slice);
    return cast(gdbstub_target_status)status;
}

private extern(C) gdbstub_target_status readMemTramp(void* ctx, uint64_t addr, uint8_t* buffer, size_t bufferLen) {
    auto c = cast(TargetContext)ctx;
    auto slice = buffer[0 .. bufferLen];
    auto status = c.callbacks.mem.readMem(addr, slice);
    return cast(gdbstub_target_status)status;
}

private extern(C) gdbstub_target_status writeMemTramp(
    void* ctx,
    uint64_t addr,
    const(uint8_t)* data,
    size_t dataLen
) {
    auto c = cast(TargetContext)ctx;
    auto slice = data[0 .. dataLen];
    auto status = c.callbacks.mem.writeMem(addr, slice);
    return cast(gdbstub_target_status)status;
}

private extern(C) gdbstub_resume_result resumeTramp(void* ctx, const(gdbstub_resume_request)* request) {
    auto c = cast(TargetContext)ctx;
    auto dRequest = toDResumeRequest(request);
    auto result = c.callbacks.run.resume(dRequest);
    return toCResumeResult(result);
}

private extern(C) void interruptTramp(void* ctx) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.run.interrupt !is null) {
        c.callbacks.run.interrupt();
    }
}

private extern(C) uint8_t pollStopTramp(void* ctx, gdbstub_stop_reason* reasonOut) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.run.pollStop is null) {
        return 0;
    }
    auto reason = c.callbacks.run.pollStop();
    if (reason.isNull) {
        return 0;
    }
    if (reasonOut !is null) {
        *reasonOut = toCStopReason(reason.get);
    }
    return 1;
}

private extern(C) void setStopNotifierTramp(void* ctx, gdbstub_stop_notifier notifier) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.run.setStopNotifier is null) {
        return;
    }
    StopNotifier wrap;
    wrap.raw = notifier;
    c.callbacks.run.setStopNotifier(wrap);
}

private extern(C) uint8_t getRunCapabilitiesTramp(void* ctx, gdbstub_run_capabilities* capsOut) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.run.getCapabilities is null) {
        return 0;
    }
    auto caps = c.callbacks.run.getCapabilities();
    if (caps.isNull) {
        return 0;
    }
    if (capsOut !is null) {
        *capsOut = toCRunCapabilities(caps.get);
    }
    return 1;
}

private extern(C) gdbstub_target_status setBreakpointTramp(void* ctx, const(gdbstub_breakpoint_spec)* spec) {
    auto c = cast(TargetContext)ctx;
    if (spec is null) {
        return gdbstub_target_status.GDBSTUB_TARGET_INVALID;
    }
    BreakpointSpec dSpec;
    dSpec.type = cast(BreakpointType)spec.type;
    dSpec.addr = spec.addr;
    dSpec.length = spec.length;
    auto status = c.callbacks.breakpoints.setBreakpoint(dSpec);
    return cast(gdbstub_target_status)status;
}

private extern(C) gdbstub_target_status removeBreakpointTramp(void* ctx, const(gdbstub_breakpoint_spec)* spec) {
    auto c = cast(TargetContext)ctx;
    if (spec is null) {
        return gdbstub_target_status.GDBSTUB_TARGET_INVALID;
    }
    BreakpointSpec dSpec;
    dSpec.type = cast(BreakpointType)spec.type;
    dSpec.addr = spec.addr;
    dSpec.length = spec.length;
    auto status = c.callbacks.breakpoints.removeBreakpoint(dSpec);
    return cast(gdbstub_target_status)status;
}

private extern(C) uint8_t getBreakpointCapabilitiesTramp(void* ctx, gdbstub_breakpoint_capabilities* capsOut) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.breakpoints.getCapabilities is null) {
        return 0;
    }
    auto caps = c.callbacks.breakpoints.getCapabilities();
    if (caps.isNull) {
        return 0;
    }
    if (capsOut !is null) {
        *capsOut = toCBreakpointCapabilities(caps.get);
    }
    return 1;
}

private extern(C) uint8_t regionInfoTramp(void* ctx, uint64_t addr, gdbstub_memory_region_info* infoOut) {
    auto c = cast(TargetContext)ctx;
    if (c.callbacks.memoryLayout.regionInfo is null) {
        return 0;
    }
    auto info = c.callbacks.memoryLayout.regionInfo(addr);
    if (info.isNull) {
        return 0;
    }
    c.regionInfoCache = info.get;
    if (infoOut !is null) {
        *infoOut = toCMemoryRegionInfo(c.regionInfoCache, c);
    }
    return 1;
}

private extern(C) gdbstub_slice_region memoryMapTramp(void* ctx) {
    auto c = cast(TargetContext)ctx;
    gdbstub_slice_region result;
    result.data = null;
    result.len = 0;
    if (c.callbacks.memoryLayout.memoryMap is null) {
        return result;
    }
    c.memoryMapCache = c.callbacks.memoryLayout.memoryMap();
    auto count = c.memoryMapCache.length;
    c.memoryMapC.length = count;
    c.memoryMapTypes.length = count;
    for (size_t i = 0; i < count; ++i) {
        auto region = c.memoryMapCache[i];
        c.memoryMapC[i].start = region.start;
        c.memoryMapC[i].size = region.size;
        c.memoryMapC[i].perms = cast(uint8_t)region.perms;
        if (region.name.isNull) {
            c.memoryMapC[i].has_name = 0;
            c.memoryMapC[i].name = gdbstub_string_view(null, 0);
        } else {
            c.memoryMapC[i].has_name = 1;
            c.memoryMapC[i].name = toStringView(region.name.get);
        }
        auto types = region.types;
        c.memoryMapTypes[i].length = types.length;
        for (size_t t = 0; t < types.length; ++t) {
            c.memoryMapTypes[i][t] = toStringView(types[t]);
        }
        c.memoryMapC[i].types.data = c.memoryMapTypes[i].ptr;
        c.memoryMapC[i].types.len = c.memoryMapTypes[i].length;
    }
    result.data = c.memoryMapC.ptr;
    result.len = count;
    return result;
}

private extern(C) gdbstub_slice_u64 threadIdsTramp(void* ctx) {
    auto c = cast(TargetContext)ctx;
    gdbstub_slice_u64 result;
    auto ids = c.callbacks.threads.threadIds();
    c.threadIdsCache.length = ids.length;
    foreach (i, id; ids) {
        c.threadIdsCache[i] = cast(uint64_t)id;
    }
    result.data = c.threadIdsCache.ptr;
    result.len = c.threadIdsCache.length;
    return result;
}

private extern(C) uint64_t currentThreadTramp(void* ctx) {
    auto c = cast(TargetContext)ctx;
    return c.callbacks.threads.currentThread();
}

private extern(C) gdbstub_target_status setCurrentThreadTramp(void* ctx, uint64_t tid) {
    auto c = cast(TargetContext)ctx;
    auto status = c.callbacks.threads.setCurrentThread(tid);
    return cast(gdbstub_target_status)status;
}

private extern(C) uint8_t threadPcTramp(void* ctx, uint64_t tid, uint64_t* valueOut) {
    auto c = cast(TargetContext)ctx;
    auto pc = c.callbacks.threads.threadPc(tid);
    if (pc.isNull) {
        return 0;
    }
    if (valueOut !is null) {
        *valueOut = pc.get;
    }
    return 1;
}

private extern(C) uint8_t threadNameTramp(void* ctx, uint64_t tid, gdbstub_string_view* nameOut) {
    auto c = cast(TargetContext)ctx;
    c.threadNameCache = c.callbacks.threads.threadName(tid);
    if (c.threadNameCache.isNull) {
        return 0;
    }
    if (nameOut !is null) {
        *nameOut = toStringView(c.threadNameCache.get);
    }
    return 1;
}

private extern(C) uint8_t threadStopReasonTramp(void* ctx, uint64_t tid, gdbstub_stop_reason* reasonOut) {
    auto c = cast(TargetContext)ctx;
    c.threadStopReasonCache = c.callbacks.threads.threadStopReason(tid);
    if (c.threadStopReasonCache.isNull) {
        return 0;
    }
    if (reasonOut !is null) {
        *reasonOut = toCStopReason(c.threadStopReasonCache.get);
    }
    return 1;
}

private extern(C) uint8_t hostInfoTramp(void* ctx, gdbstub_host_info* infoOut) {
    auto c = cast(TargetContext)ctx;
    c.hostInfoCache = c.callbacks.host.getHostInfo();
    if (c.hostInfoCache.isNull) {
        return 0;
    }
    if (infoOut !is null) {
        *infoOut = toCHostInfo(c.hostInfoCache.get);
    }
    return 1;
}

private extern(C) uint8_t processInfoTramp(void* ctx, gdbstub_process_info* infoOut) {
    auto c = cast(TargetContext)ctx;
    c.processInfoCache = c.callbacks.process.getProcessInfo();
    if (c.processInfoCache.isNull) {
        return 0;
    }
    if (infoOut !is null) {
        *infoOut = toCProcessInfo(c.processInfoCache.get);
    }
    return 1;
}

private extern(C) uint8_t shlibInfoTramp(void* ctx, gdbstub_shlib_info* infoOut) {
    auto c = cast(TargetContext)ctx;
    c.shlibInfoCache = c.callbacks.shlib.getShlibInfo();
    if (c.shlibInfoCache.isNull) {
        return 0;
    }
    if (infoOut !is null) {
        *infoOut = toCShlibInfo(c.shlibInfoCache.get);
    }
    return 1;
}

private extern(C) uint8_t registerInfoTramp(void* ctx, int regno, gdbstub_register_info* infoOut) {
    auto c = cast(TargetContext)ctx;
    c.registerInfoCache = c.callbacks.registerInfo.getRegisterInfo(regno);
    if (c.registerInfoCache.isNull) {
        return 0;
    }
    if (infoOut !is null) {
        *infoOut = toCRegisterInfo(c.registerInfoCache.get, c);
    }
    return 1;
}
