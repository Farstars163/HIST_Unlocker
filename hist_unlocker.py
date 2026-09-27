"""
HIST芝麻开门探针脚本
"""
import asyncio
import struct
import time
import json
import logging
from Crypto.Cipher import AES
from bleak import BleakClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('HIST')
try:
    with open("config.json", "r", encoding="utf-8") as f:

        cfg = json.load(f)
        CONFIG = {
            'lockMac': cfg['lockMac'],
            'aesKey': cfg['aesKey'],
            'authCode': cfg['authCode'],
            'keyGroupId': cfg['keyGroupId'],
            'timezoneOffset': cfg['timezoneOffset'],
        }
except FileNotFoundError:
    print("找不到配置文件")
    raise SystemExit(1)
except Exception as e:
    print(f"配置文件读取失败,{e}")
    raise SystemExit(1)



CMD = {
    'GET_SESSION_ID': 240, 'GET_SECRET': 241, 'GET_AUTH': 242,
    'OPEN_LOCK': 1, 'GET_DNA_INFO': 12, 'GET_SYSTEM_INFO': 13,
}
CMD_REV = {v: k for k, v in CMD.items()}

MTU_SIZE = 20


def crc16_modbus(data: bytes) -> bytes:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('>H', crc & 0xFFFF)


class HISTProtocol:
    def __init__(self, aes_key: bytes):
        self.aes_key = aes_key
        self.session_id = 0
        self.seq = 0
        self._flags = 2

    def _aes_encrypt(self, plaintext: bytes) -> bytes:
        pad = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad]) * pad
        return AES.new(self.aes_key, AES.MODE_ECB).encrypt(plaintext)

    def _aes_decrypt(self, ciphertext: bytes) -> bytes:
        dec = AES.new(self.aes_key, AES.MODE_ECB).decrypt(ciphertext)
        pad = dec[-1]
        if pad < 1 or pad > 16:
            raise ValueError(f'填充异常: {pad}')
        return dec[:-pad]

    def build_packet(self, cmd: int, iterable: bytes = b'',
                     status: int = 0, flag: int = 0, cmdVer: int = 12) -> tuple:
        snr = self.seq
        self.seq += 1

        header = struct.pack('>I', self.session_id)
        header += bytes([snr, 0, cmd, status, flag])
        header += struct.pack('>H', CONFIG['keyGroupId'])
        header += struct.pack('>H', cmdVer)

        plaintext = header + iterable
        encrypted = self._aes_encrypt(plaintext)

        # 构建HSJ帧体（用于CRC计算）
        frame_body = b'HSJ'
        pkt_len = 7 + len(encrypted) + 2
        frame_body += struct.pack('>H', pkt_len)
        frame_body += struct.pack('>H', self._flags)
        frame_body += encrypted

        # CRC计算整个frame_body（源码：s(D, D.length) 其中D=concat(G,P,C,E)）
        crc = crc16_modbus(frame_body)

        return frame_body + crc, snr

    def parse_response(self, data: bytes) -> dict:
        if data[0:3] != b'HSJ':
            raise ValueError(f'非HSJ包')
        pkt_len = struct.unpack('>H', data[3:5])[0]
        if len(data) < pkt_len:
            raise ValueError(f'包不完整')
        pkt = data[:pkt_len]
        encrypted = pkt[7:-2]
        plaintext = self._aes_decrypt(encrypted)

        if len(plaintext) < 11:
            raise ValueError(f'数据太短')
        return {
            'session_id': struct.unpack('>I', plaintext[0:4])[0],
            'snr': plaintext[4],
            'cmd': plaintext[6],
            'status': plaintext[7],
            'flag': plaintext[8],
            'kgid': struct.unpack('>H', plaintext[9:11])[0],
            'snr2': struct.unpack('>H', plaintext[11:13])[0],
            'iterable': plaintext[13:],
        }

    def set_flags(self, flags: int):
        """切换flags"""
        self._flags = flags

    def set_key(self, key: bytes):
        self.aes_key = key

    def set_session_id(self, sid: int):
        self.session_id = sid


class HISTLock:
    def __init__(self, mac: str):
        self.mac = mac.upper()
        self.client = None
        self.write_uuid = None
        self.notify_uuid = None
        self.proto = HISTProtocol(CONFIG['aesKey'].encode())
        self._response_data = {}
        self._recv_buf = b''

    def _notification_handler(self, sender, data):
        self._recv_buf += data

        while len(self._recv_buf) >= 5:
            idx = self._recv_buf.find(b'HSJ')
            if idx < 0:
                self._recv_buf = b''
                break
            if idx > 0:
                self._recv_buf = self._recv_buf[idx:]
            if len(self._recv_buf) < 5:
                break
            pkt_len = struct.unpack('>H', self._recv_buf[3:5])[0]
            if len(self._recv_buf) < pkt_len:
                break
            pkt = self._recv_buf[:pkt_len]
            self._recv_buf = self._recv_buf[pkt_len:]

            try:
                result = self.proto.parse_response(pkt)
                cmd_name = CMD_REV.get(result['cmd'], f'UNK({result["cmd"]})')
                iter_hex = result['iterable'].hex()[:48] if result['iterable'] else '空'
                log.info(f'<- {cmd_name} snr={result["snr"]} status={result["status"]} iter={iter_hex}')
                self._response_data[result['snr']] = result
            except Exception as e:
                log.warning(f'解析错误: {e}')

    async def connect(self):
        log.info(f'连接 {self.mac}...')
        self.client = BleakClient(self.mac)
        await self.client.connect(timeout=15)
        log.info(f'已连接')

        for svc in self.client.services:
            if 'FFF0' in svc.uuid.upper():
                for ch in svc.characteristics:
                    cu = ch.uuid.upper()
                    if 'FFF1' in cu:
                        self.write_uuid = ch.uuid
                    elif 'FFF2' in cu:
                        self.notify_uuid = ch.uuid
                break
        if not self.write_uuid or not self.notify_uuid:
            raise Exception('未找到特征值')
        log.info(f'写入:FFF1 通知:FFF2')
        await self.client.start_notify(self.notify_uuid, self._notification_handler)
        log.info('通知已开启')

    async def send(self, cmd: int, iterable: bytes = b'',
                   status: int = 0, flag: int = 0,
                   cmdVer: int = 12, timeout: float = 3.0) -> dict:
        pkt, snr = self.proto.build_packet(cmd, iterable, status, flag, cmdVer)
        cmd_name = CMD_REV.get(cmd, f'UNK({cmd})')
        log.info(f'-> {cmd_name} snr={snr} ({len(pkt)}B flags=0x{self.proto._flags:04x})')

        for offset in range(0, len(pkt), MTU_SIZE):
            chunk = pkt[offset:offset + MTU_SIZE]
            await self.client.write_gatt_char(self.write_uuid, chunk, response=False)
            await asyncio.sleep(0.02)

        t0 = time.time()
        while time.time() - t0 < timeout:
            if snr in self._response_data:
                return self._response_data.pop(snr)
            await asyncio.sleep(0.05)
        raise TimeoutError(f'超时: {cmd_name}')

    async def handshake(self):
        # 1. GET_SESSION_ID - flags=2, cmdVer=12
        log.info('步骤1: GET_SESSION_ID')
        self.proto.set_flags(2)
        r = await self.send(CMD['GET_SESSION_ID'], cmdVer=12)
        if r['status'] != 1:
            raise Exception(f'GET_SESSION_ID失败')
        self.proto.set_session_id(r['session_id'])

        # 2. GET_SECRET - flags=2, cmdVer=12
        log.info('步骤2: GET_SECRET')
        r = await self.send(CMD['GET_SECRET'], cmdVer=12)
        if r['status'] != 1:
            raise Exception(f'GET_SECRET失败')
        if len(r['iterable']) >= 16:
            new_key = r['iterable'][:16]
            log.info(f'新密钥: {new_key}')
            self.proto.set_key(new_key)

        # GET_SECRET成功后切换flags=3
        self.proto.set_flags(3)

        # 3. GET_AUTH - flags=3
        log.info('步骤3: GET_AUTH')
        auth = bytes.fromhex(CONFIG['authCode'])
        r = await self.send(CMD['GET_AUTH'], iterable=auth, cmdVer=12)
        if r['status'] != 1:
            raise Exception(f'GET_AUTH失败 status={r["status"]}')
        log.info('鉴权成功')

    async def unlock(self):
        log.info('步骤4: OPEN_LOCK')
        now = int(time.time())

        iterable = (b'\x00' * 4
                    + struct.pack('>I', now)
                    + struct.pack('>I', CONFIG['timezoneOffset'])[1:]
                    + struct.pack('>I', now))

        # status=6(2|4), flag=0(有authStartTime), cmdVer=21(v2)
        r = await self.send(CMD['OPEN_LOCK'], iterable=iterable,
                            status=6, flag=0, cmdVer=21, timeout=5.0)

        if r['status'] == 1:
            it = r['iterable']
            if len(it) >= 4:
                power = it[0]
                dur = it[3]
                remain = struct.unpack('>H', it[4:6])[0] if len(it) >= 6 else 0
                log.info(f'开锁成功! 电量={power}% duration={dur}s remain={remain}')
            else:
                log.info('开锁成功!')
            return True
        else:
            err = {0:'失败', 3:'远程开锁未开启', 9:'不允许开反锁',
                   10:'系统锁定', 40:'权限过期'}
            log.error(f'开锁失败: {err.get(r["status"], f"错误{r["status"]}")}')
            return False

    async def close(self):
        if self.client and self.client.is_connected:
            try:
                await self.client.stop_notify(self.notify_uuid)
            except:
                pass
            await self.client.disconnect()
            log.info('断开')


async def main():
    lock = HISTLock(CONFIG['lockMac'])
    try:
        await lock.connect()
        await lock.handshake()
        await lock.unlock()
    except Exception as e:
        log.error(f'错误: {e}', exc_info=True)
    finally:
        await lock.close()


if __name__ == '__main__':
    asyncio.run(main())