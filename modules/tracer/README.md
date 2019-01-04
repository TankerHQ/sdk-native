# Summary

The Tanker Tracer library is a small set of probes. The Tanker SDK have theses probes spread around its code base. These probes uses [lttng](https://lttng.org) to generate events (aka tracepoints) that can later be inspected.

## install

(lttng v2.10 install ppa instruction)[https://lttng.org/docs/v2.10/#doc-ubuntu-ppa]

the TL;DR is

```
$ sudo apt-add-repository ppa:lttng/stable-2.10
$ sudo apt update
$ sudo apt install lttng-tools lttng-modules-dkms liblttng-ust-dev
```

for Ubuntu 18.04 LTS. Please refer to the documentation for other distros.
Also you probably don't need the latest release, 2.10 here, but 2.10 works.

## setup

Recompile `tanker` with the 'tanker:with_tracer=True' conan flag.

if you want more reliable measurement, I highly recommend to set you cpu frequency scaling to `performance`

```
$ sudo cpupower frequency-set --governor performance
```

## generate a lttng trace

First, you have to setup a lttng session

```
$ lttng create my_session
```

Then you have to listen for lttng events. Here we want to listen only to the events provided by the Tanker Tracer library

```
$ lttng enable-event -u 'ttracer:*'
```

At anytime you can check the lttng state of thing with `lttng status`

```
$ lttng status
Tracing session bench_tanker: [inactive]
    Trace path: /home/alexandre/lttng-traces/bench_tanker-20190104-112516

=== Domain: UST global ===

Buffer type: per UID

Channels:
-------------
- channel0: [enabled]

    Attributes:
      Event-loss mode:  discard
      Sub-buffer size:  524288 bytes
      Sub-buffer count: 4
      Switch timer:     inactive
      Read timer:       inactive
      Monitor timer:    1000000 µs
      Blocking timeout: 0 µs
      Trace file count: 1 per stream
      Trace file size:  unlimited
      Output mode:      mmap

    Statistics:
      Discarded events: 0

    Event rules:
      ttracer:* (type: tracepoint) [enabled]


```

Lastly you have to start a session. If you don't, the tracepoints won't be active and nothing will be generated!

```
$ lttng start
```

`lttng status` should mark the session as `active` now.

This is when you launch your Tanker based program scenario, here we will simply launch our benchmark for `open()`:

```
$ ./bench_tanker --benchmarks-filter='^open/'
```

Once your are done, stop the session. You need to do this to flush lttng buffers, even after the program starts.

```
$ lttng stop
```

You can start/stop a lttng session whenever you want, even while your scenario is still running. Your session to be stop in order to be inspectable

## inspect a lttng trace

This is the hard part, since tooling is certainly lacking.
Your session must be stoped in order to be inspected, otherwise you see nothing.

The simplest way to view your generated tracepoint is
```
$ lttng view
```

The 'a bit less jaring' way to inspect the trace generated is to use the Tanker Tracer `inspect.py`

```
$ python3 inspect.py ~/lttng-traces/bench_tanker-20190104-112516/ust/uid/1000/64-bit/
```

This path is specific to your session name and date of creation, and also your UID. Don't be afraid to poke around the lttng generated trace directory.
