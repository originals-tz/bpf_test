// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <bpf/libbpf_common.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "leak.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    // `nm -D lib.so` or `objdump -tT leak_test`
    const char * func_name = "_Z3Newi";
    const char * target = "./leak_test";

	struct leak_bpf *skel;
	int err;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	libbpf_set_print(libbpf_print_fn);

	skel = leak_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    uprobe_opts.func_name = func_name;
	uprobe_opts.retprobe = false;
        skel->links.New = bpf_program__attach_uprobe_opts(
        skel->progs.New, 
        -1,
        target,
        0,
        &uprobe_opts);
    if (!skel->links.New) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    uprobe_opts.func_name = func_name;
	uprobe_opts.retprobe = true;
        skel->links.retNew = bpf_program__attach_uprobe_opts(
        skel->progs.retNew, 
        -1,
        target,
        0,
        &uprobe_opts);
    if (!skel->links.retNew) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    err = leak_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");
    while (true) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
	leak_bpf__destroy(skel);
	return -err;
}
