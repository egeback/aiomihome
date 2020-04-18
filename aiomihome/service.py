import asyncio
import logging
import socket
import json
import functools
import struct

from asyncio import Queue
from .gateway import MiHomeGateway
from .helpers import run_callback

_LOGGER = logging.getLogger(__name__)
MULTICAST_PORT = 9898
MULTICAST_ADDRESS = '224.0.0.50'
GATEWAY_DISCOVERY_PORT = 4321
GATEWAY_MODELS = ['gateway', 'gateway.v3', 'acpartner.v3']


class MiHomeServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, discovery_service):
        super().__init__()
        self.results = []
        self.hub_discovery_future = None
        self.futures = {}
        self.discovery_service = discovery_service
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            if len(data) is not None:
                resp = json.loads(data.decode("ascii"))

                cmd = resp['cmd']

                if cmd == 'heartbeat':
                    _LOGGER.debug('Got heartbeat {!r} from {!r}'.format(data, addr))
                    for gateway in self.discovery_service.gateways.values():
                        if gateway.sid == resp['sid'] and gateway.heartbeat_callback:
                            gateway._token = resp["token"]
                            run_callback(self.discovery_service.loop, gateway.heartbeat_callback, resp)
                    return

                elif cmd == "iam":
                    if resp["model"] not in GATEWAY_MODELS:
                        _LOGGER.error("Gateway response to iam must be valid gateway model")
                        return

                    _LOGGER.debug('Got iam {!r} from {!r}'.format(data, addr))
                    self.discovery_service._whois_queue.put_nowait(resp)
                    return
                else:
                    _LOGGER.debug('Received {!r} from {!r}'.format(data, addr))

                for gateway in self.discovery_service.gateways.values():
                    if gateway.sid == resp['sid'] and gateway.device_callback:
                        if "data" in resp:
                            gateway.decode_data(resp)
                    if addr[0] == gateway.ip_adress:
                        run_callback(self.discovery_service.loop, gateway.device_callback, resp)
        except Exception as e:
            _LOGGER.error(e, exc_info=True, stack_info=True)

class XiaomiService(object):
    def __init__(self, gateways_config=[], loop=asyncio.get_event_loop()):
        self._gateways_config = gateways_config
        self.loop = loop
        self._multicast_socket = None
        self._transport = None
        self._protocol = None
        self.disabled_gateways = []
        self.gateways = {}
        self._whois_queue = Queue()

    def get_gateways(self):
        if self.gateways:
            return [ v for v in self.gateways.values() ]
        else:
            return []
    
    async def add_gateway(self, ip_address, port, sid, key, proto="1.1.2"):
        gateway = MiHomeGateway(ip_address, port, sid, key, proto)
        self.gateways[ip_address] = gateway
        await gateway.listen()
        return gateway

    async def discover(self) -> None:
        self.gateways = {}

        for gateway in self._gateways_config:
            host = gateway.get('host')
            port = gateway.get('port')
            sid = gateway.get('sid')

            if not (host and port):
                continue

            try:
                ip_address = socket.gethostbyname(host)
                if gateway.get('disable'):
                    _LOGGER.info(
                        'Xiaomi Gateway %s is disabled by configuration', sid)
                    self.disabled_gateways.append(ip_address)
                    continue
                _LOGGER.info(
                    'Xiaomi Gateway %s configured at IP %s:%s',
                    sid, ip_address, port)

                # self.gateways[ip_address] = MiHomeGateway(
                #    ip_address, port, sid,
                #    gateway.get('key'), gateway.get('proto'))

                if not port:
                    gateway['port'] = 9898

                gateway['ip_address'] = ip_address
            except OSError as error:
                _LOGGER.error(
                    "Could not resolve %s: %s", host, error)
        
        if self._transport is None or self._multicast_socket is None:
            await self.listen()
        
        _LOGGER.debug("Discover")

        self._transport.sendto('{"cmd":"whois"}'.encode(), (MULTICAST_ADDRESS , GATEWAY_DISCOVERY_PORT))

        try:
            while True:
                gateway = await asyncio.wait_for(self._get_gateway(), 5)

                disabled = False
                for gw in self._gateways_config:
                    sid = gw.get('sid')
                    ip_address = gw.get('ip_address')
                    if (sid is None and ip_address is None) or sid == gateway.sid:
                        gateway.key = gw.get('key')
                    elif ip_address is not None and ip_address == gateway.ip_address:
                        gateway.key = gw.get('key')
                    if sid and sid == gateway.sid and gw.get('disable'):
                        disabled = True
                    elif ip_address and ip_address == gateway.ip_address and gw.get('disable'):
                        disabled = True
                    

                if disabled:
                    _LOGGER.info("Xiaomi Gateway %s is disabled by configuration", sid)
                    self.disabled_gateways.append(gateway.ip_adress)
                else:
                    _LOGGER.info('Xiaomi Gateway %s found at IP %s', gateway.sid, gateway.ip_address)
                    self.gateways[gateway.ip_address] = gateway
                    await gateway.listen()

        except asyncio.TimeoutError:
            if len(self.gateways) > 0:
                _LOGGER.debug("Gateway discovery finished in 5 seconds")
            else:
                _LOGGER.debug("Gateway discovery finished in 5 seconds, no gateways found")
        except asyncio.CancelledError:
            return
        
        _LOGGER.debug("Found %i gatways. %s", len(self.gateways), list(self.gateways.keys()))
        return [ v for v in self.gateways.values() ]
    
    async def _get_gateway(self):
        try:
            result = await self._whois_queue.get()

            return MiHomeGateway(result['ip'], int(result['port']), result['sid'], result["proto_version"] if "proto_version" in result else None, self.loop)
        except asyncio.CancelledError:
            pass
    
    async def close(self):
        _LOGGER.debug("Closing socket")
        for gateway in self.gateways.values():
            gateway.close()
        self._transport.close()
        self._multicast_socket.close()
    
    async def listen(self) -> None:
        _LOGGER.debug("Listen to multicast")
        
        self._multicast_socket = self._create_multcast_socket()
        listen = self.loop.create_datagram_endpoint(
            functools.partial(MiHomeServerProtocol, self),
            sock=self._multicast_socket,
        )

        self._transport, self._protocol = await listen

    def _create_multcast_socket(self):
        addrinfo = socket.getaddrinfo(MULTICAST_ADDRESS, None)[0]
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        
        if addrinfo[0] == socket.AF_INET: # IPv4
            sock.bind(('', MULTICAST_PORT))
            mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            sock.bind(('', MULTICAST_PORT))
            mreq = group_bin + struct.pack('@I', 0)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        
        return sock