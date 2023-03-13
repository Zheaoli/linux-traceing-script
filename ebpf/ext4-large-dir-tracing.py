from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
BPF_RINGBUF_OUTPUT(events, 65536);

struct event_data_t {
    u32 pid;
};

int trace_ext4_dx_add_entry_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret == 0) {
        return 0;
    }
    u32 pid=bpf_get_current_pid_tgid()>>32;
    struct event_data_t *event_data = events.ringbuf_reserve(sizeof(struct event_data_t));
    if (!event_data) {
        return 0;
    }
    event_data->pid = pid;
    events.ringbuf_submit(event_data, sizeof(event_data));
    return 0;
}
"""


bpf = BPF(text=bpf_text)

bpf.attach_kretprobe(event="ext4_dx_add_entry", fn_name="trace_ext4_dx_add_entry_return")

def process_event_data(cpu, data, size):
    event =  bpf["events"].event(data)
    print(f"Process {event.pid} ext4 failed")


bpf["events"].open_ring_buffer(process_event_data)

while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
