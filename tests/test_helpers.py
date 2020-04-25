import aiounittest
import asyncio
import json
import logging

from aiomihome.helpers import get_value, validate_data, validate_keyerror, list2map, parse_data

class TestService(aiounittest.AsyncTestCase):
    def test_validate_data_error(self):
        logging.basicConfig(level=logging.CRITICAL)
        j = json.loads('{"cmd":"get_id_list_ack","sid":"7811dcb07917","token":"IGji8fUXT6LiDR1i","data":"[\\"158d0001d8f319\\",\\"158d0001a2aba2\\",\\"158d00019d301b\\",\\"158d00027d8604\\"]"}')
        self.assertTrue(validate_data(j))

        j = json.loads('{"cmd":"get_id_list_ack","sid":"7811dcb07917","token":"IGji8fUXT6LiDR1i"}')
        self.assertFalse(validate_data(j))

        j = json.loads('{"cmd":"get_id_list_ack","sid":"7811dcb07917","token":"IGji8fUXT6LiDR1i","data":"{\\"error\\":\\"Test\\"}"}')
        self.assertFalse(validate_data(j))

        j = json.loads('{"cmd":"get_id_list_ack","sid":"7811dcb07917","token":"IGji8fUXT6LiDR1i","params":[{"error":"Test"}]}')
        self.assertFalse(validate_data(j))

        j = json.loads('{"cmd": "write_ack", "sid": "7811dcb07917", "data": "{\\"error\\":\\"Invalid key\\"}"}')
        self.assertTrue(validate_keyerror(j))

        j = json.loads('{"cmd": "write_ack", "sid": "7811dcb07917", "params": [{"error": "Invalid key"}]}')
        self.assertTrue(validate_keyerror(j))
        logging.basicConfig(level=logging.ERROR)

    def test_get_value(self):
        def parse(resp, key):
            return parse_data(key, get_value(resp, key))

        resp = json.loads('{"cmd":"read_ack","model":"gateway","sid":"7811dcb07917","short_id":0,"data":"{\\"rgb\\":65280,\\"illumination\\":351,\\"proto_version\\":\\"1.1.2\\"}"}')
        self.assertEqual(get_value(resp, "proto_version"), "1.1.2")
        self.assertEqual(get_value(resp, "illumination"), 351)
        self.assertEqual(get_value(resp, "rgb"), 65280)


        resp = json.loads('{"cmd":"read_ack","model":"smoke","sid":"158d0001d8f319","short_id":41686,"data":"{\\"voltage\\":3075,\\"alarm\\":\\"0\\"}"}')
        self.assertEqual(parse(resp, "voltage"), 3075)
        self.assertEqual(parse(resp, "alarm"), False)
        resp = json.loads('{"cmd":"read_ack","model":"smoke","sid":"158d0001d8f319","short_id":41686,"data":"{\\"voltage\\":3075,\\"alarm\\":\\"1\\"}"}')
        self.assertEqual(parse(resp, "alarm"), True)

        resp = json.loads('{"cmd":"read_ack","model":"sensor_ht","sid":"158d00019d301b","short_id":61974,"data":"{\\"voltage\\":3065,\\"temperature\\":\\"2332\\",\\"humidity\\":\\"3371\\"}"}')
        self.assertEqual(parse(resp, "temperature"), 23.3)
        self.assertEqual(parse(resp, "humidity"), 33.7)
