from bcc import BPF
import time
import argparse
import pandas

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

enum trace_mode {
    NFS_OPEN,
    NFS_LOOKUP,
    NFS_GET_LINK,
    NFS_FILE_READ,
    NFS_READPAGE,
    NFS_PERMISSION,
    NFS_GETATTR,
};

struct cache_data_t {
    u64 ts;
};

struct event_data_t {
    enum trace_mode mode;
    u32 pid;
    u64 delta_ts;
};

BPF_HASH(action_info, pid_t, struct cache_data_t);
BPF_RINGBUF_OUTPUT(events, 65536);


static void trace_action_enter() {
    u32 pid=bpf_get_current_pid_tgid()>>32;
    u32 tid=bpf_get_current_pid_tgid();
    if (pid!={PID}){
        return;
    }
    struct cache_data_t cache_data={};
    cache_data.ts=bpf_ktime_get_ns();
    action_info.update(&tid, &cache_data);
    return;
}

static void trace_action_return(struct pt_regs *ctx, int type) {
    u32 pid=bpf_get_current_pid_tgid()>>32;
    u32 tid=bpf_get_current_pid_tgid();
    struct cache_data_t *cache_data=action_info.lookup(&tid);
    if (cache_data==NULL){
        return;
    }
    action_info.delete(&tid);
    struct event_data_t *event_data=events.ringbuf_reserve(sizeof(struct event_data_t));
    if (!event_data) {
        return ;
    }
    event_data->mode=type;
    event_data->pid=pid;
    event_data->delta_ts=bpf_ktime_get_ns()-cache_data->ts;
    events.ringbuf_submit(event_data, sizeof(event_data));
    return;
}

int trace_nfs_open_enter(struct pt_regs *ctx, struct inode *inode, struct file *filp) {
    trace_action_enter();
    return 0;
}

int trace_nfs_open_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_OPEN);
    return 0;
}


int trace_nfs_lookup_enter(struct pt_regs *ctx, struct inode *dir, struct dentry * dentry, unsigned int flags) {
    trace_action_enter();
    return 0;
}

int trace_nfs_lookup_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_LOOKUP);
    return 0;
}

int trace_nfs_get_link_enter(struct pt_regs *ctx, struct dentry *dentry, struct inode *inode, struct delayed_call *done) {
    trace_action_enter();
    return 0;
}

int trace_nfs_get_link_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_GET_LINK);
    return 0;
}

int trace_nfs_file_read_enter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    trace_action_enter();
    return 0;
}

int trace_nfs_file_read_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_FILE_READ);
    return 0;
}

int trace_nfs_readpage_enter(struct pt_regs *ctx, struct file *file, struct page *page) {
    trace_action_enter();
    return 0;
}

int trace_nfs_readpage_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_READPAGE);
    return 0;
}

int trace_nfs_permission_enter(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *inode, int mask) {
    trace_action_enter();
    return 0;
}

int trace_nfs_permission_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_PERMISSION);
    return 0;
}

int trace_nfs_getattr_enter(struct pt_regs *ctx, struct user_namespace *mnt_userns, const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags) {
    trace_action_enter();
    return 0;
}

int trace_nfs_getattr_return(struct pt_regs *ctx) {
    trace_action_return(ctx, NFS_GETATTR);
    return 0;
}

"""

args=argparse.ArgumentParser()
args.add_argument("pid", nargs="?", default='0')

bpf_text=bpf_text.replace('{PID}', args.parse_args().pid)

bpf=BPF(text=bpf_text)

bpf.attach_kprobe(event="nfs_open", fn_name="trace_nfs_open_enter")
bpf.attach_kprobe(event="nfs_lookup", fn_name="trace_nfs_lookup_enter")
bpf.attach_kprobe(event="nfs_get_link", fn_name="trace_nfs_get_link_enter")
bpf.attach_kprobe(event="nfs_file_read", fn_name="trace_nfs_file_read_enter")
bpf.attach_kprobe(event="nfs_readpage", fn_name="trace_nfs_readpage_enter")
bpf.attach_kprobe(event="nfs_permission", fn_name="trace_nfs_permission_enter")
bpf.attach_kprobe(event="nfs_getattr", fn_name="trace_nfs_getattr_enter")

bpf.attach_kretprobe(event="nfs_open", fn_name="trace_nfs_open_return")
bpf.attach_kretprobe(event="nfs_lookup", fn_name="trace_nfs_lookup_return")
bpf.attach_kretprobe(event="nfs_get_link", fn_name="trace_nfs_get_link_return")
bpf.attach_kretprobe(event="nfs_file_read", fn_name="trace_nfs_file_read_return")
bpf.attach_kretprobe(event="nfs_readpage", fn_name="trace_nfs_readpage_return")
bpf.attach_kretprobe(event="nfs_permission", fn_name="trace_nfs_permission_return")
bpf.attach_kretprobe(event="nfs_getattr", fn_name="trace_nfs_getattr_return")


read_data=[]


def process_event_data(cpu, data, size):
    event=bpf["events"].event(data)
    result={}
    result['pid']=event.pid
    result['delta_ts']=event.delta_ts
    result['mode']=event.mode
    read_data.append(result)

bpf["events"].open_ring_buffer(process_event_data)
while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        read_df=pandas.DataFrame(read_data)
        read_df.to_csv('read_file_time_with_nas_detail.csv')
        exit()
    
