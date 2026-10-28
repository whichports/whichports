"""The file server the browser tests serve a page from, held without a browser.

    Run from site/: python3 -m pytest app/test_file_server.py

`FileServer` in test_rename_button.py says why its queue is 128 and not the
standard library's 5. What is held here is that a burst of connections which
all wait before the server accepts any, more than a page and its eight fonts,
each gets its file. With a queue of 5 on macOS 27.0.1 the first five got
theirs and every one after them failed, five runs of five. And that every
browser test that serves the fonts serves them from this server.
"""
import functools
import pathlib
import re
import socket
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_rename_button import FileServer, QuietHandler  # noqa: E402

# More connections at once than a page and its eight fonts open.
BURST = 20


def first_line(client):
    """What the server answered on one connection, or the error that came
    instead, by its class."""
    try:
        client.sendall(b"GET /f.txt HTTP/1.0\r\n\r\n")
        return client.makefile("rb").readline().strip().decode()
    except OSError as exc:
        return type(exc).__name__


def test_every_connection_that_waited_for_the_server_gets_its_file(tmp_path):
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(tmp_path))
    server = FileServer(("127.0.0.1", 0), handler)
    clients = []
    serving = False
    try:
        # All of them connect before the server accepts one, the way they do
        # when the thread that accepts is behind on a busy machine.
        for _ in range(BURST):
            clients.append(socket.create_connection(server.server_address,
                                                    timeout=10))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        serving = True
        answers = [first_line(client) for client in clients]
    finally:
        for client in clients:
            client.close()
        if serving:
            server.shutdown()
        server.server_close()
    assert answers == ["HTTP/1.0 200 OK"] * BURST, answers


def test_every_browser_test_that_serves_the_fonts_serves_them_from_this_server():
    """The fonts are the burst that filled the old queue. A test that served
    them from the standard library's server would bring the failure back."""
    here = pathlib.Path(__file__).resolve().parent
    built_bare = re.compile(r"^(?!class ).*\bThreadingHTTPServer\(", re.M)
    serving_fonts = {}
    for path in sorted(here.glob("test_*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue  # this file names the words it looks for
        text = path.read_text(encoding="utf-8")
        if "woff2" in text and "serve_forever" in text:
            serving_fonts[path.name] = text
    # The two that failed gates are found, so this cannot pass on nothing.
    assert {"test_fonts_at_depth_browser.py",
            "test_path_end_name_browser.py"} <= set(serving_fonts)
    bare = [name for name, text in serving_fonts.items()
            if built_bare.search(text) or "FileServer(" not in text]
    assert bare == []
