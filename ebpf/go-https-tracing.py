from bcc import BPF
import ctypes
import binascii

bpf_text = """
#include <linux/ptrace.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/socket.h>

struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
    u8 data[300];
    u16 data_size;
};


BPF_PERF_OUTPUT(ipv4_events);

int trace_event(struct pt_regs *ctx,struct sock *sk, struct msghdr *msg, size_t size){
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    

    // pull in details
    u16 family = sk->__sk_common.skc_family;
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    char state = sk->__sk_common.skc_state;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ip = 4;
        //data4.type = type;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // lport is host order
        data4.lport = lport;
        data4.dport = ntohs(dport);
        data4.state = state;
        struct iov_iter temp_iov_iter=msg->msg_iter;
        struct iovec *temp_iov=temp_iov_iter.iov;
        bpf_probe_read_kernel(&data4.data_size, 4, &temp_iov->iov_len);
        u8 * temp_ptr;
        bpf_probe_read_kernel(&temp_ptr, sizeof(temp_ptr), &temp_iov->iov_base);
        bpf_probe_read_kernel(&data4.data, sizeof(data4.data), temp_ptr);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }
    return 0;
}

"""

bpf = BPF(text=bpf_text)

filters = {}


def parse_ip_address(data):
    results = [0, 0, 0, 0]
    results[3] = data & 0xFF
    results[2] = (data >> 8) & 0xFF
    results[1] = (data >> 16) & 0xFF
    results[0] = (data >> 24) & 0xFF
    return ".".join([str(i) for i in results[::-1]])


def print_icmp_event(cpu, data, size):
    # event = b["probe_icmp_events"].event(data)
    # event = ctypes.cast(data, ctypes.POINTER(IcmpSamples)).contents
    event= bpf["ipv4_events"].event(data)
    daddress = parse_ip_address(event.daddr)
    # data=list(event.data)
    # temp=binascii.hexlify(data) 
    body = bytearray(event.data).hex()
    if "c0 2f c0 30 c0 2b c0 2c cc a8 cc a9 c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 13 01 13 03 13 02".replace(" ", "") in body:
        # if "68747470" in temp.decode():
        print(
            f"pid:{event.pid}, daddress:{daddress}, saddress:{parse_ip_address(event.saddr)}, {event.lport}, {event.dport}, {event.data_size}"
        )


bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_event")

bpf["ipv4_events"].open_perf_buffer(print_icmp_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
