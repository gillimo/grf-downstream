"""MIT client-only bounded encrypted transport. TLS authenticates the authority.

Requires websockets==13.1. This module does not authenticate application users;
callers MUST wrap the returned socket in verified, client-authenticated TLS.
"""
import asyncio
import base64
import hashlib
import http.client
import hmac
import json
import logging
import re
import socket
import threading
import time
from urllib.parse import quote, urlparse


FRAME_LIMIT = 65536
BYTE_LIMIT = 262144
LIFETIME = 10
LOG = logging.getLogger('grf.relay.transport')
LOG.addHandler(logging.NullHandler())
LOG.propagate = False
LOG.disabled = True
OPTIONS = dict(compression=None, max_size=FRAME_LIMIT, max_queue=4,
               read_limit=FRAME_LIMIT, write_limit=FRAME_LIMIT,
               open_timeout=8, close_timeout=1, ping_interval=15,
               ping_timeout=10, logger=LOG)


def endpoint(host, path, action, sas=None):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{4,48}\.servicebus\.windows\.net',host):
        raise ValueError('Invalid relay hostname')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',path) or action not in ('listen','connect'):
        raise ValueError('Invalid relay path/action')
    value = f'wss://{host}/$hc/{path}?sb-hc-action={action}'
    return value if sas is None else value+'&sb-hc-token='+quote(sas,safe='')


def sas_token(host, path, key_name, key, expires):
    endpoint(host,path,'listen')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',key_name):
        raise ValueError('Invalid key name')
    audience = quote('https://'+host+'/'+path,safe='')
    expiry = str(int(expires))
    signature = base64.b64encode(hmac.new(key.encode(),(audience+'\n'+expiry).encode(),hashlib.sha256).digest()).decode()
    return f'SharedAccessSignature sr={audience}&sig={quote(signature,safe="")}&se={expiry}&skn={key_name}'


async def pump(ws, reader, writer, lifetime=LIFETIME):
    """Bound bytes, messages, elapsed time and pending buffers in both directions."""
    async def upstream():
        total = 0
        while True:
            data = await reader.read(16384)
            if not data:
                return
            total += len(data)
            if total > BYTE_LIMIT:
                raise ValueError('Transport byte limit')
            await ws.send(data)

    async def downstream():
        total = 0
        async for data in ws:
            if not isinstance(data,bytes):
                raise ValueError('Binary transport required')
            total += len(data)
            if total > BYTE_LIMIT:
                raise ValueError('Transport byte limit')
            writer.write(data)
            await writer.drain()

    tasks = [asyncio.create_task(upstream()),asyncio.create_task(downstream())]
    try:
        done, _ = await asyncio.wait(tasks,timeout=lifetime,return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        writer.close()
        await writer.wait_closed()


def open_stream(host, path, sas=None):
    """Return an untrusted byte stream for immediate wrapping in verified TLS."""
    try:
        from websockets.legacy.client import connect
    except ImportError:
        raise OSError('Relay dependency is not installed') from None
    uri = endpoint(host,path,'connect',sas)
    caller, transport = socket.socketpair()
    caller.settimeout(LIFETIME)
    ready = threading.Event()
    connected = []

    async def relay():
        try:
            async with connect(uri,**OPTIONS) as ws:
                reader,writer = await asyncio.open_connection(sock=transport,limit=FRAME_LIMIT)
                connected.append(True)
                ready.set()
                await pump(ws,reader,writer)
        except Exception:
            # Exceptions can contain credential-bearing URLs; never log them.
            pass
        finally:
            transport.close()
            ready.set()

    thread = threading.Thread(target=lambda:asyncio.run(relay()),daemon=True)
    thread.start()
    if not ready.wait(10) or not connected:
        caller.close()
        transport.close()
        raise OSError('Relay connection unavailable')
    return caller



class RelayHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, config, context):
        import ssl
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError('Verified TLS required')
        super().__init__(config['host'],config['port'],context=context,timeout=4)
        self.relay=dict(config['relay'])

    def connect(self):
        from pathlib import Path
        if self._tunnel_host:
            raise ValueError('Proxy tunnels are unsupported')
        path=Path(self.relay['key_file'])
        if path.stat().st_size>512:
            raise ValueError('Invalid relay credential')
        key=path.read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[A-Za-z0-9+/=]{16,512}',key):
            raise ValueError('Invalid relay credential')
        token=sas_token(self.relay['host'],self.relay['path'],self.relay['key_name'],key,time.time()+60)
        raw=open_stream(self.relay['host'],self.relay['path'],token)
        try:
            raw.settimeout(self.timeout)
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close()
            raise
