import asyncio
import logging
import socket
import struct
import json
import functools

from asyncio import Future
from asyncio import Queue
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BROADCAST_PORT = 9898
BROADCAST_ADDR = "224.0.0.50"
#BROADCAST_ADDR = "ff0e::10"
_LOGGER = logging.getLogger(__name__)


# class Result(object):
#     def __init__(self, command,  future):
#         self.command = command
#         self.future = future

class MyHomeServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, gateways):
        super().__init__()
        self.results = []
        self.hub_discovery_future = None
        self.futures = {}
        self.gateways = gateways
        self.transport = None

    
    #def discovery_future(self, future):
    #    self.discovery_future = future

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) is not None:
            resp = json.loads(data.decode())

            cmd = resp['cmd']

            if cmd == 'heartbeat':
                print('Got heartbeat {!r} from {!r}'.format(data, addr))
            elif cmd == "iam":
                print('Got iam {!r} from {!r}'.format(data, addr))
                self.gateways._whois_queue.put_nowait(resp)
                # if self.hub_discovery_future is not None and not self.hub_discovery_future.done():
                #    self.hub_discovery_future.set_result(resp)

                    
                return
            else:
                print('Received {!r} from {!r}'.format(data, addr))
            data = "I received {!r}".format(data).encode("ascii")

        #print('Send {!r} to {!r}'.format(data, addr))
        #self.transport.sendto(data, addr)
    
    # def add_future(self, command, future):
    #     self.callbaresultscks.append(Result(command, fulture))

    # def set_hub_discovery_future(self, future):
    #    self.hub_discovery_future = future

    #def add_device_callback():
    #    pass


class MyHomeDeviceProtocol(asyncio.DatagramProtocol):
    def __init__(self, gateway):
        super().__init__()
        self.gateway = gateway
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        print('Received {!r} from {!r}'.format(data, addr))
        if len(data) is not None:
            resp = json.loads(data.decode())

            self.gateway._queue.put_nowait(resp)
        

class MyHomeGateways(object):
    def __init__(self, loop=asyncio.get_event_loop()):
        self._loop = loop
        self._multicast_socket = None
        self._transport = None
        self._protocol = None
        self._socket = None
        self._gateways = {}
        self._whois_queue = Queue()

    async def discover(self) -> None:
        if self._transport is None or self._socket is None:
            await self._listen()
        
        print("Send whois")

        # self._socket.sendto('{"cmd":"whois"}'.encode(), ('224.0.0.50' , 4321))
        self._transport.sendto('{"cmd":"whois"}'.encode(), ('224.0.0.50' , 4321))

        try:
            while True:
                gateway = await asyncio.wait_for(self._get_gateway(), 5)
                self._gateways[gateway.ip_adress] = gateway
                await gateway.listen()
        except asyncio.TimeoutError:
            _LOGGER.debug("Gateway discovery finished in 5 seconds")
        
        _LOGGER.debug("Found %i gatways. %s", len(self._gateways), list(self._gateways.keys()))
    
    async def _get_gateway(self):
        result = await self._whois_queue.get()

        return MyHomeGateway(result['ip'], int(result['port']), result['sid'], None, self._loop)

    async def _get_gateway2(self):
        future = Future()
        self._protocol.set_hub_discovery_future(future)
        await asyncio.wait_for(future, 5)
        result = future.result()
        # {"cmd":"iam","port":"9898","sid":"7811dcb07917","model":"gateway","proto_version":"1.1.2","ip":"10.0.4.104"}' from ('10.0.4.104', 4321)
        # print(result))

        return MyHomeGateway(result['ip'], int(result['port']), result['sid'], None, self._loop)
    
    async def _listen(self) -> None:
        print("listen")
        
        self._socket = self._create_multcast_socket()
        listen = self._loop.create_datagram_endpoint(
            functools.partial(MyHomeServerProtocol, self),
            sock=self._socket,
        )

        self._transport, self._protocol = await listen

    def _create_multcast_socket(self):
        addrinfo = socket.getaddrinfo(BROADCAST_ADDR, None)[0]
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        
        if addrinfo[0] == socket.AF_INET: # IPv4
            sock.bind(('', BROADCAST_PORT))
            mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            sock.bind(('', BROADCAST_PORT))
            mreq = group_bin + struct.pack('@I', 0)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        
        return sock


class MyHomeGateway(object):
    def __init__(self, ip_adress, port, sid, key, porto=None, loop=asyncio.get_event_loop()):
        self.ip_adress = ip_adress
        self.port = port
        self.sid = sid
        self.key = key
        self.proto = porto
        self._loop = loop
        self._queue = Queue()
        self._transport = None
        self._socket = None
        self._token = None
        self.devices = defaultdict(list)

    async def listen(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        listen = self._loop.create_datagram_endpoint(
            functools.partial(MyHomeDeviceProtocol, self),
            sock=self._socket,
        )

        self._transport, self._protocol = await listen

        if self.proto is None:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            resp = self._send_command(cmd)
            self.proto = _get_value(resp, "proto_version") if _validate_data(resp) else None
        self.proto = '1.0' if self.proto is None else self.proto

        await self._discover_devices()

    async def _discover_devices(self) -> None:
        # await asyncio.sleep(1)
        # print("discovery")
        # self.sock.sendto('{"cmd":"discovery"}'.encode(), ('10.0.4.104' , 9898))
        # await asyncio.sleep(1)
        # print("Send get_id_list")
        # self._socket.sendto('{"cmd" : "get_id_list"}'.encode(), ('10.0.4.104' , 9898))
        # await asyncio.sleep(1)
        # self._socket.sendto('{"cmd":"whois"}'.encode(), ('224.0.0.50' , 4321))
        # result = self.protocol.add_future("")

        command = '{"cmd" : "get_id_list"}'
        resp = await self._send_command(command, "get_id_list_ack")
        
        print(resp)

        self.token = resp['token']
        sids = []

        sids = json.loads(resp["data"])
        sids.append(self.sid)

        _LOGGER.info('Found %s devices', len(sids))

        device_types = {
            'sensor': ['sensor_ht', 'gateway', 'gateway.v3', 'weather',
                       'weather.v1', 'sensor_motion.aq2', 'acpartner.v3', 'vibration'],
            'binary_sensor': ['magnet', 'sensor_magnet', 'sensor_magnet.aq2',
                              'motion', 'sensor_motion', 'sensor_motion.aq2',
                              'switch', 'sensor_switch', 'sensor_switch.aq2', 'sensor_switch.aq3', 'remote.b1acn01',
                              '86sw1', 'sensor_86sw1', 'sensor_86sw1.aq1', 'remote.b186acn01',
                              '86sw2', 'sensor_86sw2', 'sensor_86sw2.aq1', 'remote.b286acn01',
                              'cube', 'sensor_cube', 'sensor_cube.aqgl01',
                              'smoke', 'sensor_smoke',
                              'natgas', 'sensor_natgas',
                              'sensor_wleak.aq1',
                              'vibration', 'vibration.aq1'],
            'switch': ['plug',
                       'ctrl_neutral1', 'ctrl_neutral1.aq1',
                       'ctrl_neutral2', 'ctrl_neutral2.aq1',
                       'ctrl_ln1', 'ctrl_ln1.aq1',
                       'ctrl_ln2', 'ctrl_ln2.aq1',
                       '86plug', 'ctrl_86plug', 'ctrl_86plug.aq1'],
            'light': ['gateway', 'gateway.v3'],
            'cover': ['curtain'],
            'lock': ['lock.aq1', 'lock.acn02']}

        for sid in sids:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            resp = await self._send_command(cmd, "read_ack")

            if not _validate_data(resp):
                _LOGGER.error("Not a valid device. Check the mac adress and update the firmware.")
                continue

            model = resp["model"]
            supported = False

            print(model)

            for device_type in device_types:
                if model in device_types[device_type]:
                    supported = True
                    xiaomi_device = {
                        "model": model,
                        "proto": self.proto,
                        "sid": resp["sid"],
                        "short_id": resp["short_id"] if "short_id" in resp else 0,
                        "data": _list2map(_get_value(resp)),
                        "raw_data": resp}
                    self.devices[device_type].append(xiaomi_device)
                    _LOGGER.debug('Registering device %s, %s as: %s', sid, model, device_type)

            for device_type in device_types:
                if model in device_types[device_type]:
                    xiaomi_device = {
                        "model": model,
                        "proto": self.proto,
                        "sid": resp["sid"],
                        "short_id": resp["short_id"] if "short_id" in resp else 0,
                        "data": _list2map(_get_value(resp)),
                        "raw_data": resp}
                    self.devices[device_type].append(xiaomi_device)
                    _LOGGER.debug('Registering device %s, %s as: %s', sid, model, device_type)
        
        return True

    async def _send_command(self, command, return_for_command):
        _LOGGER.debug("_send_cmd >> '%s' to: %s:%s", command.encode(), self.ip_adress, self.port)

        self._transport.sendto(command.encode(), (self.ip_adress, self.port))

        try:
            resp = await asyncio.wait_for(self._queue.get(), 10)
            _LOGGER.debug("_send_cmd resp << %s", resp)

            if return_for_command is not None and resp['cmd'] != return_for_command:
                _LOGGER.error("Non matching response. Expecting %s, but got %s", return_for_command, resp['cmd'])
                return None
            return resp

        except asyncio.TimeoutError:
            _LOGGER.error("No response from Gateway")
    
    async def write_to_gateway(self, sid, **kwargs):
        """Send data to gateway to turn on / off device"""
        if self.key is None:
            _LOGGER.error('Gateway Key is not provided. Can not send commands to the gateway.')
            return False
        data = {}
        for key in kwargs:
            data[key] = kwargs[key]
        if not self.token:
            _LOGGER.debug('Gateway Token was not obtained yet. Cannot send commands to the gateway.')
            return False
        
        cmd = dict()
        cmd['cmd'] = 'write'
        cmd['sid'] = sid
        
        data['key'] = self._get_key()
        cmd['data'] = data

        resp = self._send_cmd(json.dumps(cmd), "write_ack") if int(self.proto[0:1]) == 1 \
            else self._send_cmd(json.dumps(cmd), "write_rsp")
        _LOGGER.debug("write_ack << %s", resp)
        if _validate_data(resp):
            return True
        if not _validate_keyerror(resp):
            return False

        # If 'invalid key' message we ask for a new token
        resp = self._send_command('{"cmd" : "get_id_list"}', "get_id_list_ack") 

        _LOGGER.debug("get_id_list << %s", resp)

        if resp is None or "token" not in resp:
            _LOGGER.error('No new token from gateway. Can not send commands to the gateway.')
            return False
        self.token = resp['token']

        data['key'] = self._get_key()
        cmd['data'] = data

        resp = self._send_cmd(json.dumps(cmd), "write_ack")

        _LOGGER.debug("write_ack << %s", resp)
        return _validate_data(resp)
    
    def get_from_gateway(self, sid):
        """Get data from gateway"""
        cmd = '{ "cmd":"read","sid":"' + sid + '"}'
        resp = self._send_command(cmd, "read_ack")
        _LOGGER.debug("read_ack << %s", resp)
        return self.push_data(resp)

    def push_data(self, data):
        """Push data broadcasted from gateway to device"""
        if not _validate_data(data):
            return False
        jdata = json.loads(data['data']) if int(self.proto[0:1]) == 1 else _list2map(data['params'])
        if jdata is None:
            return False
        sid = data['sid']
        for func in self.callbacks[sid]:
            func(jdata, data)
        return True

    def _get_key(self):
        """Get key using token from gateway"""
        init_vector = bytes(bytearray.fromhex('17996d093d28ddb3ba695a2e6f58562e'))
        encryptor = Cipher(algorithms.AES(self.key.encode()), modes.CBC(init_vector),
                           backend=default_backend()).encryptor()
        ciphertext = encryptor.update(self.token.encode()) + encryptor.finalize()
        if isinstance(ciphertext, str):  # For Python 2 compatibility
            return ''.join('{:02x}'.format(ord(x)) for x in ciphertext)
        return ''.join('{:02x}'.format(x) for x in ciphertext)


def _validate_data(data):
    if data is None or ("data" not in data and "params" not in data):
        _LOGGER.error('No data in response from hub %s', data)
        return False
    if "data" in data and 'error' in json.loads(data['data']):
        _LOGGER.error('Got error element in data %s', data['data'])
        return False
    if "params" in data:
        for param in data['params']:
            if 'error' in param:
                _LOGGER.error('Got error element in data %s', data['params'])
                return False
    return True


def _validate_keyerror(data):
    if data is not None and "data" in data and 'Invalid key' in data['data']:
        return True
    if data is not None and "params" in data:
        for param in data['params']:
            if 'error' in param and 'Invalid key' in param['error']:
                return True
    return False


def _get_value(resp, data_key=None):
    if not _validate_data(resp):
        return None
    data = json.loads(resp["data"]) if "data" in resp else resp["params"]
    if data_key is None:
        return data
    if isinstance(data, list):
        for param in data:
            if data_key in param:
                return param[data_key]
        return None
    return data.get(data_key)


def _list2map(data):
    if not isinstance(data, list):
        return data
    new_data = {}
    for obj in data:
        for key in obj:
            new_data[key] = obj[key]
    new_data['raw_data'] = data
    return new_data