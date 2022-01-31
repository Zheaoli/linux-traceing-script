from bcc import BPF

bpf_text = """
BPF_PERF_OUTPUT(retrans_events);
BPF_PERF_OUTPUT(recv_events);

struct event_data_t {
    u16 sport;
    u16 dport;
    u8 saddr[4];
    u8 daddr[4];
    u32 pid;
};

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    struct event_data_t event_data={};
    event_data.sport = args->sport;
    event_data.dport = args->dport;
    event_data.pid=bpf_get_current_pid_tgid()>>32;
    bpf_probe_read_kernel(&event_data.saddr,sizeof(event_data.saddr), args->saddr);
    bpf_probe_read_kernel(&event_data.daddr,sizeof(event_data.daddr), args->daddr);
    retrans_events.perf_submit(args,&event_data, sizeof(struct event_data_t));
    return 0;
}

TRACEPOINT_PROBE(tcp, tcp_receive_reset)
{
    struct event_data_t event_data={};
    event_data.sport = args->sport;
    event_data.dport = args->dport;
    event_data.pid=bpf_get_current_pid_tgid()>>32;
    bpf_probe_read_kernel(&event_data.saddr,sizeof(event_data.saddr), args->saddr);
    bpf_probe_read_kernel(&event_data.daddr,sizeof(event_data.daddr), args->daddr);
    recv_events.perf_submit(args,&event_data, sizeof(struct event_data_t));
    return 0;
}

"""

bpf=BPF(text=bpf_text)

def process_rtrans_event_data(cpu, data, size):
    event=bpf["events"].event(data)
    print("retrans %d %d %s %s %d" % (event.sport, event.dport, ".".join([str(i) for i in event.saddr]), ".".join([str(i) for i  in event.daddr]), event.pid))

def process_recv_rst_event_data(cpu, data, size):
    event=bpf["events"].event(data)
    print("resv rst %d %d %s %s %d" % (event.sport, event.dport, ".".join([str(i) for i in event.saddr]), ".".join([str(i) for i  in event.daddr]), event.pid))

bpf["retrans_events"].open_perf_buffer(process_rtrans_event_data)

while True:
    bpf.perf_buffer_poll()