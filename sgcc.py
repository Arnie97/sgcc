#!/usr/bin/env python3

import binascii
import json
import requests
import time
from gmssl import sm2, sm3
from pipetools import pipe, X
from pprint import pprint


class SGCC(requests.Session):

    API_ROOT = "https://osg-web.sgcc.com.cn/api"
    UNCOMPRESSED_FORM = b"04"

    cipher = sm2.CryptSM2(
        private_key="11A95DF146C718B95BA6EEA75A327AB8154CFF11646FD14122B9ADA02BAFB2F7",
        public_key="04298DF4D6CCBF13F11BEEF42B96BB0323CA516E04EB4526FFB3563F3803125DB4B57FF14D8D82641C9B4E94C5975848065173F3D767706DC8403B9CB5D0BC1A58"[len(UNCOMPRESSED_FORM):],
    )

    def __init__(
        self,
        json_web_token: str,  # eyJhbGciOiJSUzUxMiJ9.eyJrZXlDb2RlIjoiMT...
        access_token: str,  # base64 after jwt in the "accessToken" header
        t_token: str,  # 98tt + 16 hex bytes in the "t" header and json bodies
        *args, **kw,
    ):
        super().__init__(*args, **kw)
        jwt_header, jwt_payload, jwt_signature = json_web_token.split('.')
        jwt_payload = json.loads(binascii.a2b_base64(jwt_payload + "===="))
        self.json_web_token = json_web_token
        self.key_code = jwt_payload["keyCode"]
        self.access_token = access_token
        self.t_token = t_token
        self.timestamp = int(time.time() * 1000)
        self.headers.update({
            "user-agent": "Mozilla/5.0",
            "authorization": "Bearer " + self.json_web_token,
            "accessToken": self.json_web_token + self.access_token,
            "timestamp": str(self.timestamp),
            "keyCode": self.key_code,
            "t": self.t_token[:18],
            "wsgwType": "http",
            "source": "0901",
            "version": "1.0",
            "retryCount": "1",
            "abc": "",
        })

    def __call__(self, path: str, payload: dict) -> dict:
        return payload > (pipe
            | self.wrap
            | json.dumps
            | str.encode
            | binascii.hexlify
            | self.cipher.encrypt
            | binascii.hexlify
            | (lambda X: self.UNCOMPRESSED_FORM + X)
            | self.sign
            | (lambda X: self.post(path, json=X).raw)
            | json.load
            | X["encryptData"]
            | X[len(self.UNCOMPRESSED_FORM):]
            | binascii.unhexlify
            | self.cipher.decrypt
            | binascii.unhexlify
            | json.loads
        )

    def wrap(self, payload: dict) -> dict:
        return dict(
            _access_token=self.access_token,
            _t=self.t_token[18:],
            _data=payload,
            timestamp=self.timestamp,
        )

    def sign(self, hex: bytes) -> dict:
        salt = self.json_web_token + self.access_token + str(self.timestamp)
        return dict(
            encryptData=hex.decode(),
            sign=sm3.sm3_hash(bytearray(hex + salt.encode())),
            timestamp=self.timestamp,
        )

    def request(self, method, path, *args, **kw):
        kw.update(stream=True, verify=False)
        return super().request(method, self.API_ROOT + path, *args, **kw)

    def tee(self, x):
        pprint(x)
        return x

    def mock(self, x):
        input(x)
        import subprocess
        return subprocess.check_output("pbpaste").strip()


if __name__ == "__main__":
    with open("tokens.json") as tokens, SGCC(**json.load(tokens)) as cli:
        pprint(cli(
            "/osg-web0004/open/c4/f01",
            dict(data={
                "partNo": "P050601",
                "issueScope": "110000",
                "iDisplayStart": 1,
                "iDisplayLength": 10,
                "siteType": "0",
                "toPublish":"01",
            })
        ))
