#!/usr/bin/python
from bcc import BPF
import collections
import ctypes
import os


class WriteData(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_int),
        ("buf", ctypes.c_char * 400),
    ]


class MarkerData(ctypes.Structure):
    _fields_ = [
        ("start", ctypes.c_int),
    ]


class EventDataUnion(ctypes.Union):
    _fields_ = [
        ("write_data", WriteData),
        ("marker_data", MarkerData),
    ]


class EventData(ctypes.Structure):
    _fields_ = [
        ("tgid", ctypes.c_int),
        ("id", ctypes.c_int),
        ("type", ctypes.c_int),
        ("data", EventDataUnion),
    ]


TMP_DIR = "/tmp/shadowterm"


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/sched/signal.h>

BPF_PERF_OUTPUT(events);

// BPF stack size limit of 512
#define BUFSIZE 400

struct write_data_t {
    int count;
    char buf[BUFSIZE];
};

struct marker_data_t {
    int start; // bool
};

enum event_type {
    MARKER_EVENT,
    WRITE_EVENT,
    EXIT_EVENT,
};

struct event_data_t {
    int tgid;
    int id;
    enum event_type type;
    union {
        struct write_data_t write_data;
        struct marker_data_t marker_data;
    };
};

int handle_readline_enter(struct pt_regs *ctx) {
    int tgid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    int id = cur->signal->tty->session->numbers[0].nr;

    struct event_data_t data = {
        .tgid = tgid,
        .id = id,
        .type = MARKER_EVENT,
        .marker_data = {
            .start = 1,
        },
    };

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int handle_readline_ret(struct pt_regs *ctx) {
    int tgid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    int id = cur->signal->tty->session->numbers[0].nr;

    struct event_data_t data = {
        .tgid = tgid,
        .id = id,
        .type = MARKER_EVENT,
        .marker_data = {
            .start = 0,
        },
    };

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int handle_tty_write(struct pt_regs *ctx, struct file *file, const char *buf, size_t count) {
    if (file->f_inode->i_ino == _DAEMON_TTY_INODE_) {
        return 0;
    }

    int tgid = bpf_get_current_pid_tgid() >> 32;

    struct tty_struct *tty = ((struct tty_file_private *)file->private_data)->tty;

    struct event_data_t data = {
        .tgid = tgid,
        .id = tty->session->numbers[0].nr,
        .type = WRITE_EVENT,
    };

    bpf_probe_read_user(&data.write_data.buf, BUFSIZE, (void *)buf);
    if (count > BUFSIZE)
        data.write_data.count = BUFSIZE;
    else
        data.write_data.count = count;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int handle_exit(struct pt_regs *ctx) {
    int tgid = bpf_get_current_pid_tgid() >> 32;
    struct event_data_t data = {
        .tgid = tgid,
        .type = EXIT_EVENT,
    };
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

bpf_text = bpf_text.replace('_DAEMON_TTY_INODE_', str(os.stat("/proc/self/fd/1").st_ino))

b = BPF(text=bpf_text)
b.attach_kprobe(event="tty_write", fn_name="handle_tty_write")
b.attach_kprobe(event="do_group_exit", fn_name="handle_exit")

SHELL = "/bin/bash"
b.attach_uprobe(name=SHELL, sym="readline", fn_name="handle_readline_enter")
b.attach_uretprobe(name=SHELL, sym="readline", fn_name="handle_readline_ret")


if not os.path.exists(TMP_DIR):
    os.makedirs(TMP_DIR)


session_is_writing = collections.defaultdict(lambda: False)


def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    session_fn_base = os.path.join(TMP_DIR, str(event.id))

    if event.type == 0:
        session_is_writing[event.id] = not event.data.marker_data.start
        if session_is_writing[event.id]:
            try:
                os.rename(f"{session_fn_base}-1", f"{session_fn_base}-0")
            except Exception:
                pass

    elif event.type == 1:
        if session_is_writing[event.id]:
            buf = event.data.write_data.buf[0:event.data.write_data.count]
            with open(f"{session_fn_base}-1", 'ab') as f:
                f.write(buf)

    elif event.type == 2:
        if event.tgid in session_is_writing:
            try:
                os.unlink(f"{event.tgid}-0")
            except Exception:
                pass
            try:
                os.unlink(f"{event.tgid}-1")
            except Exception:
                pass


b["events"].open_perf_buffer(handle_event)


while 1:
    b.perf_buffer_poll()
