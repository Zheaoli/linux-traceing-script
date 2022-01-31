from bcc import BPF,Tracepoint

bpf_text = """
BPF_RINGBUF_OUTPUT(events, 65536);

struct event_data_t {
    u16 sport;
    u16 dport;
    u8 saddr[4];
    u8 daddr[4];
};

RAW_TRACEPOINT_PROBE(tcp_retransmit_skb){
    struct event_data_t *event_data=events.ringbuf_reserve(sizeof(struct event_data_t));
    data.sport = ctx->args[2];
    data.dport = ctx->args[3];
    data.saddr = ctx->args[4];
    data.daddr = ctx->args[5];
    events.ringbuf_submit(event_data, sizeof(struct event_data_t));
}

"""

def parse_ip_address(data):
    results = [0, 0, 0, 0]
    results[3] = data & 0xFF
    results[2] = (data >> 8) & 0xFF
    results[1] = (data >> 16) & 0xFF
    results[0] = (data >> 24) & 0xFF
    return ".".join([str(i) for i in results[::-1]])

bpf=BPF(text=bpf_text)

def process_event_data(cpu, data, size):
    event=bpf["events"].event(data)
    print("%d %d %s %s" % (event.sport, event.dport, parse_ip_address(event.saddr), parse_ip_address(event.daddr)))

bpf["events"].open_ring_buffer(process_event_data)

while True:
    bpf.ring_buffer_consume()
    


