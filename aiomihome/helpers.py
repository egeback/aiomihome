import asyncio
import logging
import json


_LOGGER = logging.getLogger(__name__)


def run_callback(loop, callback, *args, **kwargs):
    if asyncio.iscoroutine(callback):
            loop.create_task(callback)
    elif asyncio.iscoroutinefunction(callback):
        loop.create_task(callback(*args, **kwargs))
    else:
        loop.run_in_executor(None, callback, args, kwargs)

def list2map(data):
    if not isinstance(data, list):
        return data
    new_data = {}
    for obj in data:
        for key in obj:
            new_data[key] = obj[key]
    new_data['raw_data'] = data
    return new_data


def encode_light_rgb(brightness, red, green, blue):
    """Encode rgb value used to control the gateway light"""
    return (brightness << 24) + (red << 16) + (green << 8) + blue

def decode_light_rgb(c):
    bri = (c>>24)&0xff
    r = (c>>16)&0xff
    g = (c>>8)&0xff
    b = c&0xff

    return {"brightness": bri, "red": r, "green": g, "blue": b}

def is_int(s):
    if isinstance(s, int):
        return True
    elif isinstance(s, str):
        if s[0] in ('-', '+'):
            return s[1:].isdigit()
        return s.isdigit()
    
    return False

def validate_data(data):
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


def validate_keyerror(data):
    if data is not None and "data" in data and 'Invalid key' in data['data']:
        return True
    if data is not None and "params" in data:
        for param in data['params']:
            if 'error' in param and 'Invalid key' in param['error']:
                return True
    return False


def get_value(resp, data_key=None):
    if not validate_data(resp):
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