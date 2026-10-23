#!/bin/bash
s=$1
ssh rw-man-01 "docker exec nl2 bash /t/clean.sh; docker exec nl2 sh -c 'cd /t && export NETLAB_POWER_CUTS=1 && timeout 1200 bash /t/$s > /t/out-$s.log 2>&1; echo exit=\$? >> /t/out-$s.log; tail -${2:-40} /t/out-$s.log'"
