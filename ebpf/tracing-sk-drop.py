import argparse
from bcc import BPF
import ctypes

bpf_text = """
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/inet_sock.h>

struct event_data_t {
    u32 pid;
    u16 sport;
    u16 dport;
    u32 daddress;
    u32 saddress;
};

BPF_RINGBUF_OUTPUT(events, 65536);
BPF_HASH(action_info, pid_t, struct event_data_t);

int trace_sk_drop_event_enter(struct pt_regs *ctx, const struct sock *sk, struct sk_buff *skb) {
    __u16 sport = 0, dport = 0;
    __be32 saddr = 0, daddr = 0;
    u32 pid = bpf_get_current_pid_tgid()>>32;
    u32 tid = bpf_get_current_pid_tgid();
    if (pid!={PID}) {
        return 0;
    }
    if (sk->__sk_common.skc_family != AF_INET){
        return 0;
    }
    struct inet_sock *inet_sk = (struct inet_sock *)sk; 
    struct event_data_t event_data = {};
    event_data.pid = pid;
    event_data.sport = inet_sk->inet_sport;
    event_data.dport = inet_sk->inet_dport;
    event_data.saddress=inet_sk->inet_saddr;
    event_data.daddress=inet_sk->inet_daddr;
    action_info.update(&tid, &event_data);
    return 0;
}
int trace_sk_drop_event_return(struct pt_regs *ctx) {
    u32 pid=bpf_get_current_pid_tgid()>>32;
    u32 tid=bpf_get_current_pid_tgid();
    if (pid!={PID}) {
        return 0;
    }
    struct sock* ret = PT_REGS_RC(ctx);

    struct event_data_t *event_data=action_info.lookup(&tid);
    if (event_data==NULL){
        return 0;
    }
    action_info.delete(&tid);
    if (!ret) {
        return 0;
    }
    struct event_data_t *new_event_data = events.ringbuf_reserve(sizeof(struct event_data_t));
    if (!new_event_data){
        return 0;
    }
    new_event_data->pid=event_data->pid;
    new_event_data->sport=event_data->sport;
    new_event_data->dport=event_data->dport;
    new_event_data->daddress=event_data->daddress;
    new_event_data->saddress=event_data->saddress;
    events.ringbuf_submit(new_event_data, sizeof(new_event_data));
}



"""

class EventSamples(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("daddress", ctypes.c_uint32),
        ("saddress", ctypes.c_uint32),
    ]

args = argparse.ArgumentParser()
args.add_argument("pid", nargs="?", default="0")
bpf_text = bpf_text.replace("{PID}", args.parse_args().pid)
bpf = BPF(text=bpf_text)
bpf.attach_kprobe(event="tcp_v4_syn_recv_sock", fn_name="trace_sk_drop_event_enter")
bpf.attach_kretprobe(event="tcp_v4_syn_recv_sock", fn_name="trace_sk_drop_event_return")


def parse_ip_address(data):
    results = [0, 0, 0, 0]
    results[3] = data & 0xFF
    results[2] = (data >> 8) & 0xFF
    results[1] = (data >> 16) & 0xFF
    results[0] = (data >> 24) & 0xFF
    return ".".join([str(i) for i in results[::-1]])


def process_event_data(cpu, data, size):
    # event = b["probe_icmp_events"].event(data)
    event = ctypes.cast(data, ctypes.POINTER(EventSamples)).contents
    daddress = parse_ip_address(event.daddress)
    print(
        f"pid:{event.pid}, daddress:{daddress}, saddress:{parse_ip_address(event.saddress)}, sport:{event.sport}, dport:{event.dport}"
    )

bpf["events"].open_ring_buffer(process_event_data)

while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
