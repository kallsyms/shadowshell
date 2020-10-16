#!/usr/bin/env python3
from typing import List
from bcc import BPF

import collections
import ctypes
import logging
import os
import sys

from config import TMP_DIR


class WriteData(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_int),
        ("buf", ctypes.c_char * 400),
    ]


class MarkerData(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
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


"""
Enter: ioctl(x, TCSETSW, ECHO)
Exit: last TIOCSPGRP before tty_read
"""

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/sched/signal.h>

BPF_HASH(session_state, int, int);
BPF_PERF_OUTPUT(events);

// BPF stack size limit of 512
#define BUFSIZE 400

struct write_data_t {
    int count;
    char buf[BUFSIZE];
};

struct marker_data_t {
    int type;
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

int kprobe__tty_write(struct pt_regs *ctx, struct file *file, const char *buf, size_t count) {
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

int kprobe__tty_mode_ioctl(struct pt_regs *ctx, struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg) {
    int tgid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    int id = cur->signal->tty->session->numbers[0].nr;

    if (tgid == id && cmd == TCSETSW) {
        struct termios t;
        bpf_probe_read_user(&t, sizeof(t), (void*)arg);

        if (t.c_lflag & ECHO) {
            int state = 1;
            session_state.update(&id, &state);

            struct event_data_t data = {
                .tgid = tgid,
                .id = id,
                .type = MARKER_EVENT,
                .marker_data = {
                    .type = 0,
                },
            };
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    return 0;
}

int kprobe__tty_jobctrl_ioctl(struct pt_regs *ctx, struct tty_struct *tty, struct tty_struct *real_tty, struct file *file, unsigned int cmd, unsigned long arg) {
    int tgid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    int id = cur->signal->tty->session->numbers[0].nr;

    if (tgid == id && cmd == TIOCSPGRP) {
        int new_pgrp;
        bpf_probe_read_user(&new_pgrp, sizeof(new_pgrp), (int*)arg);

        if (tgid == new_pgrp) {
            struct event_data_t data = {
                .tgid = tgid,
                .id = id,
                .type = MARKER_EVENT,
                .marker_data = {
                    .type = 1,
                }
            };
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    return 0;
}

int kprobe__tty_read(struct pt_regs *ctx, struct file *file, const char *buf, size_t count, loff_t *ppos) {
    if (file->f_inode->i_ino == _DAEMON_TTY_INODE_) {
        return 0;
    }

    int tgid = bpf_get_current_pid_tgid() >> 32;

    struct tty_struct *tty = ((struct tty_file_private *)file->private_data)->tty;
    int id = tty->session->numbers[0].nr;

    if (session_state.lookup(&id) == NULL) {
        return 0;
    }

    session_state.delete(&id);

    struct event_data_t data = {
        .tgid = tgid,
        .id = id,
        .type = MARKER_EVENT,
        .marker_data = {
            .type = 2,
        },
    };

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int kprobe__do_group_exit(struct pt_regs *ctx) {
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


class SessionState(object):
    is_writing: bool
    cmd_offsets: List[int]

    def __init__(self):
        self.is_writing = False
        self.cmd_offsets = [0]


session_states = collections.defaultdict(lambda: SessionState())


def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    session_fn_base = os.path.join(TMP_DIR, str(event.id))

    if event.type == 0:
        # Marker
        marker_type = event.data.marker_data.type
        state = session_states[event.id]

        if marker_type == 0:
            logging.debug("%d: Start marker received", event.id)
            state.is_writing = True

        elif marker_type == 1:
            with open(f"{session_fn_base}-1", 'ab') as f:
                logging.debug("%d: (Potentially) intermediate shell process group set leader. Marking output at %d", event.id, f.tell())
                session_states[event.id].cmd_offsets.append(f.tell())

        elif marker_type == 2:
            with open(f"{session_fn_base}-1", 'ab') as f:
                end_of_cmds = session_states[event.id].cmd_offsets[-1]
                logging.debug("%d: tty_read. Truncating output to %d", event.id, end_of_cmds)
                f.truncate(end_of_cmds)

            logging.debug("%d: Renaming current log to 0", event.id)
            os.rename(f"{session_fn_base}-1", f"{session_fn_base}-0")

            session_states[event.id].is_writing = False

        else:
            logging.warning("Unknown marker type %d received for session %d from TGID %d", marker_type, event.id, event.tgid)

    elif event.type == 1:
        # Write data
        if session_states[event.id].is_writing:
            buf = event.data.write_data.buf[0:event.data.write_data.count]

            logging.debug("%d: Data received (len = %d): %s", event.id, event.data.write_data.count, buf)

            with open(f"{session_fn_base}-1", 'ab') as f:
                f.write(buf)
                f.flush()

    elif event.type == 2:
        # Exit
        if event.tgid in session_states:
            logging.debug("%d: Exit received, cleaning up", event.id)

            try:
                os.unlink(f"{event.tgid}-0")
            except Exception:
                pass
            try:
                os.unlink(f"{event.tgid}-1")
            except Exception:
                pass

    else:
        logging.warning("Unknown event type %d", event.type)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == "-v":
        logging.basicConfig(level=logging.DEBUG)

    if not os.path.exists(TMP_DIR):
        os.makedirs(TMP_DIR)

    # BCC does some stuff that makes it hard to trap KeyboardInterrupt
    def excepthook(exctype, value, traceback):
        if exctype == KeyboardInterrupt:
            sys.exit(0)
        else:
            sys.__excepthook__(exctype, value, traceback)
    sys.excepthook = excepthook

    b = BPF(text=bpf_text)
    b["events"].open_perf_buffer(handle_event)

    while 1:
        b.perf_buffer_poll()
