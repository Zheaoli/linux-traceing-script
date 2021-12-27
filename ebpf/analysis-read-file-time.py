from bcc import BPF
import time
import argparse
import pandas

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

enum trace_mode {
    MODE_READ,
    MODE_WRITE,
};

struct cache_data_t {
    u32 data_size;
    u64 ts;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
};

struct event_data_t {
    enum trace_mode mode;
    u32 pid;
    u32 data_size;
    u64 delta_ts;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
};

BPF_HASH(action_info, pid_t, struct cache_data_t);
BPF_PERF_OUTPUT(events);


static void trace_vfs_rw_action(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    u32 pid=bpf_get_current_pid_tgid()>>32;
    u32 tid=bpf_get_current_pid_tgid();
    if (pid!={PID}){
        return;
    }
    struct dentry *dentry = file->f_path.dentry;
    int mode=file->f_inode->i_mode;
    if (dentry->d_name.len==0||!S_ISREG(mode)){
        return;
    }
    struct cache_data_t cache_data={};
    cache_data.data_size=count;
    cache_data.ts=bpf_ktime_get_ns();
    bpf_probe_read_kernel(&cache_data.name, sizeof(cache_data.name), dentry->d_name.name);
    action_info.update(&tid, &cache_data);
    return;
}

static void trace_vfs_rw_action_return(struct pt_regs *ctx, int type) {
    u32 pid=bpf_get_current_pid_tgid()>>32;
    u32 tid=bpf_get_current_pid_tgid();
    struct cache_data_t *cache_data=action_info.lookup(&tid);
    if (cache_data==NULL){
        return;
    }
    action_info.delete(&tid);
    struct event_data_t event_data={};
    event_data.mode=type;
    event_data.pid=pid;
    event_data.data_size=cache_data->data_size;
    event_data.delta_ts=bpf_ktime_get_ns()-cache_data->ts;
    bpf_probe_read_kernel(&event_data.name, sizeof(event_data.name), cache_data->name);
    events.perf_submit(ctx, &event_data, sizeof(event_data));
    return;
}

int trace_vfs_rw_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    if (!(file->f_op->read_iter)&&!(file->f_op->write_iter)){
        return 0;
    }
    trace_vfs_rw_action(ctx, file, buf, count);
    return 0;
}

int trace_vfs_read_exit(struct pt_regs *ctx){
    trace_vfs_rw_action_return(ctx, MODE_READ);
    return 0;
}

int trace_vfs_write_exit(struct pt_regs *ctx){
    trace_vfs_rw_action_return(ctx, MODE_WRITE);
    return 0;
}

"""

args=argparse.ArgumentParser()
args.add_argument("pid", nargs="?", default='0')

bpf_text=bpf_text.replace('{PID}', args.parse_args().pid)

bpf=BPF(text=bpf_text)

bpf.attach_kprobe(event="vfs_read", fn_name="trace_vfs_rw_entry")
bpf.attach_kprobe(event="vfs_write", fn_name="trace_vfs_rw_entry")
bpf.attach_kretprobe(event="vfs_read", fn_name="trace_vfs_read_exit")
bpf.attach_kretprobe(event="vfs_write", fn_name="trace_vfs_write_exit")

read_data=[]
write_data=[]


def process_event_data(cpu, data, size):
    event=bpf["events"].event(data)
    result={}
    result['pid']=event.pid
    result['data_size']=event.data_size
    result['delta_ts']=event.delta_ts
    result['name']=event.name.decode("utf-8", "replace")
    if event.mode==0:
        read_data.append(result)
    else:
        write_data.append(result)

bpf["events"].open_perf_buffer(process_event_data)
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        read_df=pandas.DataFrame(read_data)
        write_df=pandas.DataFrame(write_data)
        read_df.to_csv('read_file_time_with_nas.csv')
        write_df.to_csv('write_file_time_with_nas.csv')
        exit()
    
