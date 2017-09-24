By default `scp` and `sftp` do not allow agent forwarding. If you wish to use
these commands with the recording proxy, the following aliases are useful.

```
alias sftp='sftp -S ./withagent.py'
alias scp='scp -S ./withagent.py'
```

Where `withagent.py` is below.


```python
#!/usr/bin/env python

import sys
import subprocess


def remove_no_forward(argv):
    args = argv[1:]

    remove_list = [
       "-oClearAllForwardings yes",
       "-oClearAllForwardings=yes",
       "-oForwardAgent no",
       "-oForwardAgent=no"]

    for remove_item in remove_list:
        if remove_item in args: args.remove(remove_item)

    return args


def build_command(args):
    ssh_path = ["/usr/bin/ssh"]
    proxy_command_arg = ["-o", "ProxyCommand ssh -p 3023 %r@proxy.example.com -s proxy:%h:%p"]

    return ssh_path + proxy_command_arg + args


if __name__ == "__main__":
    # strip deny of agent forwarding
    args = remove_no_forward(sys.argv)

    # build command to run
    argv = build_command(args)

    # debug command
    #sys.stderr.write(str(argv))

    # run command
    subprocess.call(argv)
```
