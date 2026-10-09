# app.py — SOCKS5 proxy with username/password auth (final, crash-resistant)
# Python 3.11+ | stdlib only | target: FPS.ms container
# protocol: RFC 1928 (SOCKS5) + RFC 1929 (user/pass auth)

import asyncio
import logging
import os
import signal
import socket
import struct
import sys
import time

# ═══════════════════════════════════════════════════════════════
#  CONFIG — اینجا رو چک کن
# ═══════════════════════════════════════════════════════════════
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 30855                 # پورت عمومی FPS.ms

PROXY_USER = "YourUserName"
PROXY_PASS = "YourPassword"

CONNECT_TIMEOUT = 15                # timeout اتصال به مقصد
BUFFER_SIZE     = 65536
MAX_CONNECTIONS = 500
# ═══════════════════════════════════════════════════════════════

VER              = 5
METHOD_USERPASS  = 2
METHOD_NONE      = 0xFF
CMD_CONNECT      = 1
ATYP_IPV4        = 1
ATYP_DOMAIN      = 3
ATYP_IPV6        = 4
REP_SUCCESS      = 0
REP_GENERAL      = 1
REP_NOT_ALLOWED  = 2
REP_NET_UNREACH  = 3
REP_HOST_UNREACH = 4
REP_REFUSED      = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("socks5")

_active = 0
_active_lock = asyncio.Lock()


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """One-way forward. Never raises."""
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError,
            BrokenPipeError, TimeoutError, OSError):
        pass
    finally:
        try:
            if not writer.is_closing():
                writer.close()
        except Exception:
            pass


async def close_silent(writer):
    try:
        if writer and not writer.is_closing():
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass
    except Exception:
        pass


async def handle_client(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
    global _active

    peer = writer.get_extra_info("peername")
    peer_str = f"{peer[0]}:{peer[1]}" if peer else "?"

    remote_writer = None
    try:
        async with _active_lock:
            _active += 1

        # ── 1. greeting ─────────────────────────────────────────
        try:
            header = await asyncio.wait_for(read_exact(reader, 2), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        ver, nmethods = header[0], header[1]
        if ver != VER:
            return

        try:
            methods = await asyncio.wait_for(read_exact(reader, nmethods), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        if METHOD_USERPASS not in methods:
            writer.write(struct.pack("!BB", VER, METHOD_NONE))
            await writer.drain()
            return

        writer.write(struct.pack("!BB", VER, METHOD_USERPASS))
        await writer.drain()

        # ── 2. RFC 1929 auth ────────────────────────────────────
        try:
            _          = await asyncio.wait_for(read_exact(reader, 1), timeout=10)
            ulen_b     = await asyncio.wait_for(read_exact(reader, 1), timeout=10)
            uname_b    = await asyncio.wait_for(read_exact(reader, ulen_b[0]), timeout=10)
            plen_b     = await asyncio.wait_for(read_exact(reader, 1), timeout=10)
            passwd_b   = await asyncio.wait_for(read_exact(reader, plen_b[0]), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        uname  = uname_b.decode("utf-8", errors="replace")
        passwd = passwd_b.decode("utf-8", errors="replace")

        if uname != PROXY_USER or passwd != PROXY_PASS:
            writer.write(struct.pack("!BB", 1, 1))
            await writer.drain()
            log.warning(f"auth fail {peer_str} user={uname!r}")
            return

        writer.write(struct.pack("!BB", 1, 0))
        await writer.drain()

        # ── 3. request ──────────────────────────────────────────
        try:
            req = await asyncio.wait_for(read_exact(reader, 4), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        ver, cmd, _, atyp = req
        if ver != VER or cmd != CMD_CONNECT:
            writer.write(struct.pack("!BBBB", VER, REP_NOT_ALLOWED, 0, ATYP_IPV4)
                         + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        # ── 4. destination address ──────────────────────────────
        try:
            if atyp == ATYP_IPV4:
                raw = await read_exact(reader, 4)
                dest_host = socket.inet_ntoa(raw)
            elif atyp == ATYP_DOMAIN:
                ln = (await read_exact(reader, 1))[0]
                dest_host = (await read_exact(reader, ln)).decode(
                    "utf-8", errors="replace")
            elif atyp == ATYP_IPV6:
                raw = await read_exact(reader, 16)
                dest_host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(struct.pack("!BBBB", VER, REP_NOT_ALLOWED, 0, ATYP_IPV4)
                             + b"\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            dest_port = struct.unpack("!H", await read_exact(reader, 2))[0]
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            return

        # ── 5. DNS (sync, در executor) + connect ────────────────
        loop = asyncio.get_running_loop()

        try:
            dest_ip = await loop.run_in_executor(
                None, socket.gethostbyname, dest_host)
        except Exception as e:
            log.warning(f"DNS fail {dest_host}: {e}")
            writer.write(struct.pack("!BBBB", VER, REP_HOST_UNREACH, 0, ATYP_IPV4)
                         + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(dest_ip, dest_port),
                timeout=CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.warning(f"timeout {dest_ip}:{dest_port}")
            writer.write(struct.pack("!BBBB", VER, REP_HOST_UNREACH, 0, ATYP_IPV4)
                         + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        except (ConnectionRefusedError, OSError) as e:
            log.warning(f"refused {dest_ip}:{dest_port}: {e}")
            writer.write(struct.pack("!BBBB", VER, REP_REFUSED, 0, ATYP_IPV4)
                         + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        # reply success
        writer.write(struct.pack("!BBBB", VER, REP_SUCCESS, 0, ATYP_IPV4)
                     + b"\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        log.info(f"open {peer_str} -> {dest_host} ({dest_ip}):{dest_port}")

        # ── 6. bidirectional pipe ───────────────────────────────
        await asyncio.gather(
            pipe(reader, remote_writer),
            pipe(remote_reader, writer),
            return_exceptions=True,
        )

    except asyncio.CancelledError:
        raise
    except Exception as e:
        log.error(f"handler err {peer_str}: {e}")
    finally:
        await close_silent(remote_writer)
        await close_silent(writer)
        async with _active_lock:
            _active -= 1


async def main():
    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
        reuse_address=True,
        backlog=512,
        limit=BUFFER_SIZE * 2,
    )

    for sock in server.sockets:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    log.info(f"SOCKS5 proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"auth: user={PROXY_USER} pass={'*' * len(PROXY_PASS)}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _shutdown(*_):
        log.info("shutdown signal received")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError):
            pass

    async with server:
        serve = asyncio.create_task(server.serve_forever())
        await stop.wait()
        serve.cancel()
        try:
            await serve
        except asyncio.CancelledError:
            pass

    log.info("proxy stopped")


if __name__ == "__main__":
    while True:
        try:
            asyncio.run(main())
            break
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f"fatal: {e} — restarting in 5s")
            time.sleep(5)