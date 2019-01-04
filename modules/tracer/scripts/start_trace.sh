#!/bin/sh
lttng create bench_tanker && lttng enable-event -u 'ttracer:*' && lttng start
