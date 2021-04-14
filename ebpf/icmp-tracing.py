from bcc import BPF
import ctypes

bpf_text = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

struct probe_icmp_sample {
    u32 pid;
    u32 daddress;
    u32 saddress;
};

BPF_PERF_OUTPUT(probe_events);

static inline unsigned char *custom_skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}

static inline struct iphdr *get_iphdr_in_icmp(const struct sk_buff *skb)
{
    return (struct iphdr *)custom_skb_network_header(skb);
}

int probe_icmp(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb){
    struct iphdr * ipdata=get_iphdr_in_icmp(skb);
    if (ipdata->protocol!=1){
        return 1;
    }
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    u32 __pid = __pid_tgid;
    struct probe_icmp_sample __data = {0};
    __data.pid = __pid;
    u32 daddress;
    u32 saddress;
    bpf_probe_read(&daddress, sizeof(ipdata->daddr), &ipdata->daddr);
    bpf_probe_read(&saddress, sizeof(ipdata->daddr), &ipdata->saddr);
    __data.daddress=daddress;
    __data.saddress=saddress;
    probe_events.perf_submit(ctx, &__data, sizeof(__data));
    return 0;
}

"""


class IcmpSamples(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("daddress", ctypes.c_uint32),
        ("saddress", ctypes.c_uint32),
    ]


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
    event = ctypes.cast(data, ctypes.POINTER(IcmpSamples)).contents
    daddress = parse_ip_address(event.daddress)
    print(
        f"pid:{event.pid}, daddress:{daddress}, saddress:{parse_ip_address(event.saddress)}"
    )


bpf.attach_kprobe(event="ip_finish_output", fn_name="probe_icmp")

bpf["probe_events"].open_perf_buffer(print_icmp_event)
while 1:
    try:
        bpf.kprobe_poll()
    except KeyboardInterrupt:
        exit()
