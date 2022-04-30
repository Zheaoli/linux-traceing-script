from bcc import BPF
import struct
import socket

bpf_text = """
#include <linux/ptrace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>
#include <linux/socket.h>

BPF_RINGBUF_OUTPUT(events, 65536);


struct event_data_t {
    u16 state;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u16 type;
};

static struct event_data_t * generate_event_data(struct sock *sk) {
    struct event_data_t *event_data=events.ringbuf_reserve(sizeof(struct event_data_t));
    if (!event_data) {
        return NULL;
    }

    event_data->state = sk->__sk_common.skc_state;
    event_data->saddr = sk->__sk_common.skc_rcv_saddr;
    event_data->daddr = sk->__sk_common.skc_daddr;
    event_data->lport = sk->__sk_common.skc_num;
    event_data->dport = sk->__sk_common.skc_dport;
    return event_data;
}

int trace_tcp_fin(struct pt_regs *ctx, struct sock *sk) {
    u16 state = sk->__sk_common.skc_state;
    if (state != TCP_FIN_WAIT2) {
        return 0;
    }
    struct event_data_t *event_data=generate_event_data(sk);
    if (!event_data) {
        return 0;
    }
    event_data->type = 1;
    
    events.ringbuf_submit(event_data, sizeof(event_data));
    return 0;
}

int trace_tcp_send_fin(struct pt_regs *ctx, struct sock *sk) {
    u16 state = sk->__sk_common.skc_state;
    if (state != TCP_FIN_WAIT1) {
        return 0;
    }
    struct event_data_t *event_data=generate_event_data(sk);
    if (!event_data) {
        return 0;
    }

    event_data->type = 2;
    
    events.ringbuf_submit(event_data, sizeof(event_data));
    return 0;
}




"""

bpf = BPF(text=bpf_text)

bpf.attach_kprobe(event="tcp_fin", fn_name="trace_tcp_fin")
bpf.attach_kprobe(event="tcp_send_fin", fn_name="trace_tcp_send_fin")


def parse_ip_address(data):
    results = [0, 0, 0, 0]
    results[3] = data & 0xFF
    results[2] = (data >> 8) & 0xFF
    results[1] = (data >> 16) & 0xFF
    results[0] = (data >> 24) & 0xFF
    return ".".join([str(i) for i in results[::-1]])


def process_event_data(cpu, data, size):
    event = bpf["events"].event(data)
    print(
        f"Source Address:{parse_ip_address(event.saddr)}, Source Port: {event.lport}, Dest Address: {parse_ip_address(event.daddr)}, Dest Port: {socket.ntohs(event.dport)}, State: {event.state}, Action {'Send FIN' if event.type==2 else 'Receive FIN'}"
    )


bpf["events"].open_ring_buffer(process_event_data)
while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
