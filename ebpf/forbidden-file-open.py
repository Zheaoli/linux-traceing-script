import argparse
from bcc import BPF
from numpy import byte

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>


struct event_data_t {
    u32 pid;
    int status;
    char data[{length}];
};

static inline bool equal_to_true(char *str) {
  char comparand[{length}];
  bpf_probe_read_user(&comparand, sizeof(comparand), str);
  char compare[] = "{file_name}";
  for (int i = 0; i < {length}; ++i)
    if (compare[i] != comparand[i])
      return false;
  return true;
}


BPF_RINGBUF_OUTPUT(events, 65536);
int trace_sys_openat(struct pt_regs *ctx) {

    u32 pid=bpf_get_current_pid_tgid()>>32;
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char __user *filename ;
    bpf_probe_read_kernel(&filename, sizeof(filename), &(PT_REGS_PARM2(__ctx)));
    if (filename==NULL){
        return 0;
    }
    if (equal_to_true(filename)){
        struct event_data_t *event_data = events.ringbuf_reserve(sizeof(struct event_data_t));
        if (!event_data) {
            return 0;
        }
        event_data->pid = pid;
        bpf_probe_read_user(&event_data->data, sizeof(event_data->data), filename);
        bpf_override_return(ctx, -EACCES);
        events.ringbuf_submit(event_data, sizeof(event_data));
    }
    return 0;
}
"""
args = argparse.ArgumentParser()
args.add_argument("filename", nargs="?", default="")

filename=args.parse_args().filename
print(filename)

bpf_text = bpf_text.replace("{file_name}", filename).replace("{length}", str(len(filename)))

bpf = BPF(text=bpf_text)

bpf.attach_kprobe(event="__x64_sys_openat", fn_name="trace_sys_openat")

def process_event_data(cpu, data, size):
    event =  bpf["events"].event(data)
    print(f"Process {event.pid} try to open {filename} but is forbidden,{event.status}, {event.data}")

bpf["events"].open_ring_buffer(process_event_data)
while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()



