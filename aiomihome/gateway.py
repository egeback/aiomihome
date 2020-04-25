import asyncio
import logging
import socket
import json
import functools

from asyncio import Future
from asyncio import Queue
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .helpers import _list2map, encode_light_rgb, decode_light_rgb, is_int


GATEWAY_DISCOVERY_PORT = 4321
_LOGGER = logging.getLogger(__name__)


class MiHomeDeviceProtocol(asyncio.DatagramProtocol):
    def __init__(self, gateway):
        super().__init__()
        self.gateway = gateway
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        _LOGGER.debug('Received {!r} from {!r}'.format(data, addr))
        if len(data) is not None:
            resp = json.loads(data.decode("ascii"))

            self.gateway._queue.put_nowait(resp)

class MiHomeGateway(object):
    def __init__(self,address, port, sid, key, porto=None, loop=asyncio.get_event_loop(), host=None):
        self.ip_address = address
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
        self.callbacks = defaultdict(list)
        self.host = host
        self.heartbeat_callback = None
        self.device_callback = None

        self.brightness = -1
        self.color = -1
        self.illumination = -1
        self.rgb = -1

    async def listen(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        listen = self._loop.create_datagram_endpoint(
            functools.partial(MiHomeDeviceProtocol, self),
            sock=self._socket,
        )

        self._transport, self._protocol = await listen

        if self.proto is None:
            cmd = '{"cmd":"read","sid":"' + self.sid + '"}'
            resp = await self._send_command(cmd)
            self.proto = _get_value(resp, "proto_version") if _validate_data(resp) else None

        self.proto = '1.0' if self.proto is None else self.proto

        trycount = 5
        for _ in range(trycount):
            _LOGGER.info('Discovering Xiaomi Devices')
            if  await self._discover_devices():
                break
    
    def close(self):
        _LOGGER.debug("Closing Gateway")
        self._transport.close()
        self._socket.close()

    async def _discover_devices(self) -> None:
        command = '{"cmd" : "get_id_list"}'
        resp = await self._send_command(command, "get_id_list_ack")

        if resp is None or "token" not in resp or ("data" not in resp and "dev_list" not in resp):
            return False

        self._token = resp['token']
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

            if resp["sid"] == self.sid:
                self.decode_data(resp)

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

            if not supported:
                if model:
                    _LOGGER.error(
                        'Unsupported device found! %s', resp)
                else:
                    _LOGGER.error(
                        'The device with sid %s isn\'t supported of the used '
                        'gateway firmware. Please update the gateway firmware if '
                        'possible! This is the only way the issue can be solved.',
                        resp["sid"])

                continue        
        return True

    async def _send_command(self, command, return_for_command=None):
        _LOGGER.debug("_send_cmd >> '%s' to: %s:%s", command.encode(), self.ip_address,  self.port)

        self._transport.sendto(command.encode(), (self.ip_address,  self.port))

        if return_for_command is None:
            return None
        try:
            resp = await asyncio.wait_for(self._queue.get(), 10)
            _LOGGER.debug("_send_cmd resp << %s", resp)

            if return_for_command is not None and resp['cmd'] != return_for_command:
                _LOGGER.error("Non matching response. Expecting %s, but got %s", return_for_command, resp['cmd'])
                return None
            return resp

        except asyncio.TimeoutError:
            _LOGGER.error("No response from Gateway")
        
        return None
    
    async def send_cmd(self, **kwargs):
        return await self._write_data(self.sid, **kwargs)
    
    async def _write_data(self, sid, **kwargs):
        """Send data to gateway to turn on / off device"""
        if self.key is None:
            _LOGGER.error('Gateway Key is not provided. Can not send commands to the gateway.')
            return False
        data = {}
        for key in kwargs:
            data[key] = kwargs[key]
        if not self._token:
            _LOGGER.debug('Gateway Token was not obtained yet. Cannot send commands to the gateway.')
            return False
        
        cmd = dict()
        cmd['cmd'] = 'write'
        cmd['sid'] = sid

        data['key'] = self._get_key()
        cmd['data'] = data

        resp = await self._send_command(json.dumps(cmd), "write_ack")
        _LOGGER.debug("write_ack << %s", resp)
        if _validate_data(resp):
            return True
        if not _validate_keyerror(resp):
            return False

        # If 'invalid key' message we ask for a new token
        resp = await self._send_command('{"cmd" : "get_id_list"}', "get_id_list_ack") 

        _LOGGER.debug("get_id_list << %s", resp)

        if resp is None or "token" not in resp:
            _LOGGER.error('No new token from gateway. Can not send commands to the gateway.')
            return False
        self._token = resp['token']

        data['key'] = self._get_key()
        cmd['data'] = data

        resp = await self._send_command(json.dumps(cmd), "write_ack")

        _LOGGER.debug("write_ack << %s", resp)
        return _validate_data(resp)
    
    def get_data(self, sid):
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
        ciphertext = encryptor.update(self._token.encode()) + encryptor.finalize()
        if isinstance(ciphertext, str):  # For Python 2 compatibility
            return ''.join('{:02x}'.format(ord(x)) for x in ciphertext)
        return ''.join('{:02x}'.format(x) for x in ciphertext)

    async def set_color(self, r, g, b, brightness=-1):
        if brightness > 0:
            await self.send_cmd(**{"rgb": encode_light_rgb(brightness, r, b , b)})
        else:
            await self.send_cmd(**{"rgb": encode_light_rgb(self.brightness, r, g , b)})
    
    async def turn_off_light(self):
        await self.send_cmd(**{"rgb": 0})
    
    def decode_data(self, data):
        if isinstance(data, str):
            j_data = json.loads(data)
        elif isinstance(data, list):
            j_data = _list2map(_get_value(data))
        else:
            j_data = data
        
        if "data" in j_data:
            j_data = j_data["data"]
            if isinstance(j_data, str):
                j_data = json.loads(j_data)
        
        if "illumination" in j_data:
            self.illumination = j_data.get("illumination")
        if "rgb" in j_data:
            self.rgb = j_data.get("rgb")
            c = decode_light_rgb(j_data.get("rgb"))
            brightness = c["brightness"]
            del c["brightness"]
            self.color = c


def _validate_data(data):
    if data is None or ("data" not in data and "params" not in data):
        _LOGGER.error('No data in response from hub %s', data)
        return False
    if "data" in data and 'error' in json.loads(data['data']):
        _LOGGER.error("Got error element in data %s, full data: '%s'", data['data'], data)
        return False
    if "params" in data:
        for param in data['params']:
            if 'error' in param:
                _LOGGER.error("Got error element in data %s, full data: '%s'", data['params'], data)
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
        #if isinstance(data, dict):
        #    new_data = {}
        #    for key, value in data.items():
        #        new_data[key] = parse_data(key, value)
        #    return new_data
        return data
    if isinstance(data, list):
        for param in data:
            if data_key in param:
                return param[data_key]
        return None
    return data.get(data_key)

def parse_data(value_key, value):
    """Parse data sent by gateway."""
    if value is None:
        return False
    elif value_key in ["coordination", "status", "proto", "proto_version"] or not is_int(value):
        return value
    elif value_key in ["alarm"]:
        return False if value == "0" else True
    elif value_key in ["rgb"]:
        return int(value)
    
    value = float(value)
    if value_key in ["temperature", "humidity", "pressure"]:
        value /= 100
    elif value_key in ["illumination"]:
        value = max(value - 300, 0)
    if value_key == "temperature" and (value < -50 or value > 60):
        return False
    if value_key == "humidity" and (value <= 0 or value > 100):
        return False
    if value_key == "pressure" and value == 0:
        return False
    if value_key in ["illumination", "lux"]:
        return round(value)
    else:
        return round(value, 1)
    
    return value