from bcc import BPF

bpf_text = """
BPF_RINGBUF_OUTPUT(tcp_event, 65536);

enum tcp_event_type {
    retrans_event,
    recv_rst_event,
};

struct event_data_t {
    enum tcp_event_type type;
    u16 sport;
    u16 dport;
    u8 saddr[4];
    u8 daddr[4];
    u32 pid;
};

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    struct event_data_t event_data={};
    event_data.type = retrans_event;
    event_data.sport = args->sport;
    event_data.dport = args->dport;
    event_data.pid=bpf_get_current_pid_tgid()>>32;
    bpf_probe_read_kernel(&event_data.saddr,sizeof(event_data.saddr), args->saddr);
    bpf_probe_read_kernel(&event_data.daddr,sizeof(event_data.daddr), args->daddr);
    tcp_event.ringbuf_output(args,&event_data, sizeof(struct event_data_t), 0);
    return 0;
}

TRACEPOINT_PROBE(tcp, tcp_receive_reset)
{
    struct event_data_t event_data={};
    event_data.type = recv_rst_event;
    event_data.sport = args->sport;
    event_data.dport = args->dport;
    event_data.pid=bpf_get_current_pid_tgid()>>32;
    bpf_probe_read_kernel(&event_data.saddr,sizeof(event_data.saddr), args->saddr);
    bpf_probe_read_kernel(&event_data.daddr,sizeof(event_data.daddr), args->daddr);
    tcp_event.ringbuf_output(args,&event_data, sizeof(struct event_data_t), 0);
    return 0;
}

"""

bpf = BPF(text=bpf_text)


def process_event_data(cpu, data, size):
    event = bpf["tcp_event"].event(data)
    event_type = "retransmit" if event.type == 0 else "recv_rst"
    print(
        "%s %d %d %s %s %d"
        % (
            event_type,
            event.sport,
            event.dport,
            ".".join([str(i) for i in event.saddr]),
            ".".join([str(i) for i in event.daddr]),
            event.pid,
        )
    )


bpf["tcp_event"].open_ring_buffer(process_event_data)


while True:
    bpf.ring_buffer_consume()
