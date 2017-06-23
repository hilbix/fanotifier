> **Some parts (flags, +-event) are still missing, nearly not tested, some options have bugs**


# fanotifier

This just dumps all `fanotify()` events of the given mounts to stdout in a shell parsable way.  By default it monitors the mount of the current directory.


## Usage

    git clone https://github.com/hilbix/fanotifier.git
    cd fanotifier
    make
    sudo make install

To run:

    sudo ./fanotifier


## Options

- You do not need to know anything.  By default it just outputs everything for the given mount(s).
- Add/remove events using `-EVENT` and `+EVENT`.  `EVENT` is what you find in the first column of the output.
- To ignore events from a given `PID` (second column in output), use `-PID`, where `PID` is a number.  It always ignores it's own `PID` (else it might deadlock).  It is recommended to add `-1` if you do not need it.  There is a special `-0` which means, ignore all processes which currently exist.
- There are some additional options, which are enabled using `+NR` notation.  `NR` is a bit-mask of following numbers.  Note that the last variant of `+` wins, so `+0` resets all flags:
  - `0` mount mode.  Use `FAN_MARK_MOUNT`.
  - `1` file mode.  Do not use `FAN_MARK_MOUNT`
  - `2` dir mode.  Use `FAN_MARK_ONLYDIR`
  - `3` dir+child mode.  Use `FAN_EVENT_ON_CHILD`
  - `4` ignore directories.  Do not use `FAN_ONDIR`.
  - `8` verbose operation.
  - `16` unbuffered output.
  - `32` blocking mode.  Use this option for more reliable synthetic events.  However it slows down other processes, so if you halt `fanotifier` your system might come to a standstill.
  - `64` unlimited queue.  Sets the `FAN_UNLIMITED_QUEUE` option
  - `128` unlimited marks.  Sets the `FAN_UNLIMITED_MARKS` option
  - `256` follow softlinks.  Do not use `FAN_MARK_DONT_FOLLOW`
  - `512` do not quote 3rd column (better human readable)
  - `1024` output empty separation lines (better human readable)
  - `2048` (future use)
  - `4096` (future use)
  - `8192` (future use)
  - `16384` (future use)
  - `32768` debugging
  - `65536` and above: future use

Output:

- `flag` `TAB` `PID` `TAB` `Filename` `LF`
- The `flag` is according to `fanotify(7)` without the `FAN_` prefix.  If more than one event is present, it is printed in `EVENT1|EVENT2`-Notation.
- The `PID` is the process id which raised the event
- Filename takes the rest of the line.  If is escaped according to `bash`'s `printf %b` format.

Example how to use:

    while read -ru6 flag pid _name
    do
       printf -v name '%b' "$_name"
       got_event "$flag" "$pid" "$name"
    done 6< <(fanotifier)


## Synthetic events

If `fanotify` detects a new process ID (or changes), it sends out following synthetic events:

- `CWD` which shows the current working directory (read from `/proc/PID/cwd`)
- `PROC` which shows the process (read from `/proc/PID/exe`)
- `PPID` which shows the parent of the fork.  The 3rd column is just a number (the parent process ID)

This is poor man's "who forked what and where".


## License

This Works is placed under the terms of the Copyright Less License,
see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.

Read: This is free as in free beer, free speech, free baby.

