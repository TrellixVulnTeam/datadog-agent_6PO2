#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    __builtin_memset(buf, 0, sz);

    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();

    if (BPF_CORE_READ_STR_INTO(buf, cur_tsk, cgroups, subsys[0], cgroup, kn, name))
        return -1;

    return 0;
}

#endif /* defined(BPF_COMMON_H) */
