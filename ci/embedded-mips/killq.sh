#!/bin/sh
for p in /proc/[0-9]*; do case "$(cat $p/comm 2>/dev/null)" in qemu-system-mip*) kill -9 ${p#/proc/};; esac; done
