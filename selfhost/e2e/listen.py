"""The test target's main process: two listening TCP ports, on both families.

80 and 8080 accept a connection and close it. That is all a TCP connect probe
needs, and the agent on this host reads both sockets as listening.
"""
import socket
import threading

PORTS = (80, 8080)


def serve(port: int) -> None:
    # One dual-stack socket: IPv6 with V6ONLY off also accepts IPv4.
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", port))
    server.listen(16)
    while True:
        connection, _peer = server.accept()
        connection.close()


threads = [threading.Thread(target=serve, args=(port,)) for port in PORTS]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
