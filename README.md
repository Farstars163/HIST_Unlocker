# HIST_Unlocker

## 获取参数

1. ![1](docs/1.png)
2. ![2](docs/2.png)
3. ![3](docs/3.png)
4. ![4](docs/4.png)
5. ![5](docs/5.png)

## Python 版

```bash
pip install pycryptodome bleak
```
将模板 `config.example.json`重命名为config.json，并按照实际获取的参数信息填写对应字段:

⚠️⚠️⚠️：为了保障人身安全，请不要将信息泄漏⚠️⚠️⚠️

填写 `config.json`：

| 字段 | 说明 |
| --- | --- |
| lockMac | 门锁蓝牙 MAC |
| aesKey | 16 字节密钥 |
| authCode | 鉴权码 |
| keyGroupId | 密钥组 ID |
| timezoneOffset | 时区偏移 |

```bash
python hist_unlocker.py
```

## Android 版

`HistUnlocker.kt` 顶部 `companion object` 中填入 `LOCK_MAC`、`AES_KEY`、`AUTH_CODE`、`KEY_GROUP_ID`，授权后点「一键开锁」。

源码位于 `apk/`，`./gradlew assembleDebug` 构建。
