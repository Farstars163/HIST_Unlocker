package com.hist.unlock

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

@SuppressLint("MissingPermission")
class HistUnlocker(private val ctx: Context) {

    companion object {
        private const val TAG = "HIST_Unlocker"
        const val LOCK_MAC = "AA:BB:CC:DD:EE:FF"
        val AES_KEY = "0000000000000000".toByteArray(Charsets.UTF_8)
        val AUTH_CODE = hexToBytes("00000000")
        const val KEY_GROUP_ID = 0
        const val TIMEZONE_OFFSET = 480
        const val MTU = 20

        const val CMD_GET_SESSION_ID = 240
        const val CMD_GET_SECRET     = 241
        const val CMD_GET_AUTH       = 242
        const val CMD_OPEN_LOCK      = 1

        fun hexToBytes(s: String): ByteArray =
            s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    // ============ BLE 状态 ============
    private var gatt: BluetoothGatt? = null
    private var writeChar: BluetoothGattCharacteristic? = null
    private var notifyChar: BluetoothGattCharacteristic? = null

    // ============ 协议状态 ============
    private var sessionId: Long = 0
    private var seq: Int = 0
    private var aesKey: ByteArray = AES_KEY
    private var flags: Int = 2

    private val recvBuf = StringBuilder()
    private var pendingSnr: Int = -1
    private var pendingResult: CompletableDeferred<ResponseData>? = null
    private var connectDeferred: CompletableDeferred<Boolean>? = null
    private var writeDeferred: CompletableDeferred<Unit>? = null
    private var needDescriptorWrite: Boolean = false
    private var descriptorWritten: Boolean = false

    private var scope: CoroutineScope? = null
    private var currentJob: Job? = null

    var onStatus: ((String) -> Unit)? = null
    var onSuccess: ((String) -> Unit)? = null
    var onError: ((String) -> Unit)? = null

    val isConnected: Boolean
        get() = gatt != null && writeChar != null && notifyChar != null

    data class ResponseData(
        val sessionId: Long,
        val snr: Int,
        val cmd: Int,
        val status: Int,
        val flag: Int,
        val kgid: Int,
        val cmdVer: Int,
        val iterable: ByteArray
    )

    // ============ BLE 回调 ============
    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gattParam: BluetoothGatt, status: Int, newState: Int) {
            Log.d(TAG, "BLE_connState gatt=$gattParam st=$status new=$newState myGatt=${this@HistUnlocker.gatt}")
            if (gattParam != this@HistUnlocker.gatt) {
                Log.w(TAG, "  -> 忽略过时回调")
                return
            }
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    Log.d(TAG, "  -> 已连接,开始发现服务")
                    gattParam.discoverServices()
                } else {
                    Log.e(TAG, "连接状态异常 status=$status")
                    failConnect("连接状态异常 status=$status")
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.w(TAG, "设备断开连接")
                failConnect("设备断开连接")
                failPending("设备断开连接")
            }
        }

        override fun onServicesDiscovered(gattParam: BluetoothGatt, status: Int) {
            Log.d(TAG, "BLE_svcDisc status=$status myGatt=${this@HistUnlocker.gatt}")
            if (gattParam != this@HistUnlocker.gatt) {
                Log.w(TAG, "  -> 忽略过时回调")
                return
            }
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "服务发现失败 status=$status")
                failConnect("服务发现失败 status=$status")
                return
            }

            writeChar = null
            notifyChar = null
            needDescriptorWrite = false
            descriptorWritten = false

            var foundService = false
            for (svc in gattParam.services) {
                if (!svc.uuid.toString().uppercase().contains("FFF0")) continue
                foundService = true
                Log.d(TAG, "  -> 找到FFF0服务,遍历特征...")
                for (ch in svc.characteristics) {
                    val cu = ch.uuid.toString().uppercase()
                    when {
                        cu.contains("FFF1") -> {
                            writeChar = ch
                            Log.d(TAG, "  -> 找到FFF1写入特征")
                            // 门锁只支持 WRITE_TYPE_NO_RESPONSE
                            ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                        }
                        cu.contains("FFF2") -> {
                            notifyChar = ch
                            Log.d(TAG, "  -> 找到FFF2通知特征")
                            gattParam.setCharacteristicNotification(ch, true)
                            val cccd = ch.getDescriptor(
                                UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                            )
                            cccd?.let {
                                it.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                                needDescriptorWrite = true
                                gattParam.writeDescriptor(it)
                            }
                        }
                    }
                }
                break
            }

            if (!foundService) {
                Log.e(TAG, "  -> 未找到FFF0服务!")
                failConnect("未找到FFF0服务，请确认门锁型号兼容")
                return
            }
            if (writeChar == null) {
                Log.e(TAG, "  -> 特征FFF1(写入)未找到!")
                failConnect("特征FFF1(写入)未找到")
                return
            }
            if (notifyChar == null) {
                Log.e(TAG, "  -> 特征FFF2(通知)未找到!")
                failConnect("特征FFF2(通知)未找到")
                return
            }

            Log.d(TAG, "  -> 所有特征就绪，尝试完成连接")
            // 请求 MTU 更新，让后续数据包尽量一次写完
            gattParam.requestMtu(512)
            tryCompleteConnect()
        }

        override fun onCharacteristicChanged(gattParam: BluetoothGatt, ch: BluetoothGattCharacteristic) {
            if (gattParam != this@HistUnlocker.gatt) return
            ch.value?.let { data ->
                val hex = data.joinToString("") { "%02X".format(it) }
                Log.d(TAG, "BLE_notify: $hex")
                recvBuf.append(hex)
                processBuffer()
            }
        }

        override fun onDescriptorWrite(gattParam: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (gattParam != this@HistUnlocker.gatt) return
            Log.d(TAG, "BLE_descWrite st=$status")
            descriptorWritten = true
            tryCompleteConnect()
        }

        override fun onCharacteristicWrite(gattParam: BluetoothGatt, ch: BluetoothGattCharacteristic, status: Int) {
            if (gattParam != this@HistUnlocker.gatt) return
            Log.d(TAG, "BLE_write st=$status")
            val d = writeDeferred
            writeDeferred = null
            if (status == BluetoothGatt.GATT_SUCCESS) {
                d?.complete(Unit)
            } else {
                d?.completeExceptionally(Exception("BLE写入失败 status=$status"))
            }
        }

        override fun onMtuChanged(gattParam: BluetoothGatt, mtu: Int, status: Int) {
            if (gattParam != this@HistUnlocker.gatt) return
            Log.d(TAG, "BLE_mtu mtu=$mtu st=$status")
        }
    }

    // ============ 连接/断开辅助 ============
    private fun tryCompleteConnect() {
        if (writeChar == null || notifyChar == null) return
        if (needDescriptorWrite && !descriptorWritten) return
        val d = connectDeferred
        connectDeferred = null
        Log.d(TAG, "连接成功!")
        d?.complete(true)
    }

    private fun failConnect(msg: String) {
        val d = connectDeferred
        connectDeferred = null
        d?.complete(false)
    }

    private fun failPending(msg: String) {
        val p = pendingResult
        pendingResult = null
        pendingSnr = -1
        if (p != null && !p.isCompleted) {
            p.completeExceptionally(Exception(msg))
        }
    }

    // ============ 接收缓冲解析 ============
    private fun processBuffer() {
        while (true) {
            val idx = recvBuf.indexOf("48534A")
            if (idx < 0) {
                recvBuf.clear()
                return
            }
            if (idx > 0) recvBuf.delete(0, idx)

            if (recvBuf.length < 10) return

            val pktLen = recvBuf.substring(6, 10).toInt(16)
            val hexNeeded = pktLen * 2
            if (recvBuf.length < hexNeeded) return

            val hexPacket = recvBuf.substring(0, hexNeeded)
            recvBuf.delete(0, hexNeeded)

            try {
                val raw = hexToBytes(hexPacket)
                val resp = parseResponse(raw)
                if (resp.snr == pendingSnr) {
                    Log.d(TAG, "  -> 匹配响应 snr=${resp.snr} cmd=${resp.cmd} st=${resp.status}")
                    val p = pendingResult
                    pendingResult = null
                    pendingSnr = -1
                    p?.complete(resp)
                } else {
                    Log.d(TAG, "  -> 跳过响应 snr=${resp.snr} pendingSnr=$pendingSnr")
                }
            } catch (_: Exception) {}
        }
    }

    // ============ AES ============
    private fun aesEncrypt(plaintext: ByteArray): ByteArray {
        val padLen = 16 - (plaintext.size % 16)
        val padded = plaintext + ByteArray(padLen) { padLen.toByte() }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        return cipher.doFinal(padded)
    }

    private fun aesDecrypt(ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val dec = cipher.doFinal(ciphertext)
        val padLen = dec.last().toInt() and 0xFF
        if (padLen < 1 || padLen > 16) throw IllegalArgumentException("填充异常: $padLen")
        return dec.copyOf(dec.size - padLen)
    }

    // ============ CRC16 ============
    private fun crc16(data: ByteArray): ByteArray {
        var crc = 0xFFFF
        for (b in data) {
            crc = crc xor (b.toInt() and 0xFF)
            repeat(8) {
                crc = if ((crc and 1) == 1) (crc shr 1) xor 0xA001 else crc shr 1
            }
        }
        return byteArrayOf(((crc shr 8) and 0xFF).toByte(), (crc and 0xFF).toByte())
    }

    // ============ 构建数据包 ============
    private fun buildPacket(cmd: Int, iterable: ByteArray = byteArrayOf(), status: Int = 0, flag: Int = 0, cmdVer: Int = 12): Pair<ByteArray, Int> {
        val snr = seq; seq++
        val header = ByteArray(13)
        var p = 0
        for (i in 3 downTo 0) header[p++] = ((sessionId shr (i * 8)) and 0xFF).toByte()
        header[p++] = snr.toByte()
        header[p++] = 0
        header[p++] = cmd.toByte()
        header[p++] = status.toByte()
        header[p++] = flag.toByte()
        header[p++] = ((KEY_GROUP_ID shr 8) and 0xFF).toByte()
        header[p++] = (KEY_GROUP_ID and 0xFF).toByte()
        header[p++] = ((cmdVer shr 8) and 0xFF).toByte()
        header[p]   = (cmdVer and 0xFF).toByte()

        val plaintext = header + iterable
        val encrypted = aesEncrypt(plaintext)

        val pktLen = 7 + encrypted.size + 2
        val frameBody = ByteArray(pktLen - 2)
        var fp = 0
        frameBody[fp++] = 'H'.code.toByte()
        frameBody[fp++] = 'S'.code.toByte()
        frameBody[fp++] = 'J'.code.toByte()
        frameBody[fp++] = ((pktLen shr 8) and 0xFF).toByte()
        frameBody[fp++] = (pktLen and 0xFF).toByte()
        frameBody[fp++] = ((flags shr 8) and 0xFF).toByte()
        frameBody[fp++] = (flags and 0xFF).toByte()
        encrypted.copyInto(frameBody, fp)

        val crc = crc16(frameBody)
        return Pair(frameBody + crc, snr)
    }

    // ============ 解析响应 ============
    private fun parseResponse(data: ByteArray): ResponseData {
        if (data.size < 5) throw IllegalArgumentException("数据太短")
        if (data[0] != 'H'.code.toByte() || data[1] != 'S'.code.toByte() || data[2] != 'J'.code.toByte())
            throw IllegalArgumentException("非HSJ包")
        val pktLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        if (data.size < pktLen) throw IllegalArgumentException("包不完整")
        val encrypted = data.copyOfRange(7, pktLen - 2)
        val plaintext = aesDecrypt(encrypted)
        if (plaintext.size < 13) throw IllegalArgumentException("明文太短")
        return ResponseData(
            sessionId = ((plaintext[0].toLong() and 0xFF) shl 24) or ((plaintext[1].toLong() and 0xFF) shl 16) or
                        ((plaintext[2].toLong() and 0xFF) shl 8) or (plaintext[3].toLong() and 0xFF),
            snr      = plaintext[4].toInt() and 0xFF,
            cmd      = plaintext[6].toInt() and 0xFF,
            status   = plaintext[7].toInt() and 0xFF,
            flag     = plaintext[8].toInt() and 0xFF,
            kgid     = ((plaintext[9].toInt() and 0xFF) shl 8) or (plaintext[10].toInt() and 0xFF),
            cmdVer   = ((plaintext[11].toInt() and 0xFF) shl 8) or (plaintext[12].toInt() and 0xFF),
            iterable = if (plaintext.size > 13) plaintext.copyOfRange(13, plaintext.size) else byteArrayOf()
        )
    }

    // ============ 发送命令并等待响应 ============
    private suspend fun sendCmd(cmd: Int, iterable: ByteArray = byteArrayOf(), status: Int = 0, flag: Int = 0, cmdVer: Int = 12, timeoutMs: Long = 5000): ResponseData {
        val (pkt, snr) = buildPacket(cmd, iterable, status, flag, cmdVer)
        Log.d(TAG, "sendCmd cmd=$cmd snr=$snr")

        val ch = writeChar ?: throw Exception("写入特征不可用")
        pendingSnr = snr
        pendingResult = CompletableDeferred()

        val g = gatt ?: throw Exception("BLE未连接")

        var offset = 0
        while (offset < pkt.size) {
            val chunkSize = min(MTU, pkt.size - offset)
            val chunk = pkt.copyOfRange(offset, offset + chunkSize)
            ch.value = chunk
            val wd = CompletableDeferred<Unit>()
            writeDeferred = wd
            if (!g.writeCharacteristic(ch)) {
                writeDeferred = null
                pendingResult?.cancel()
                throw Exception("写入特征失败（GATT忙）")
            }
            // ★ 用本地引用 wd 而非 writeDeferred，防止回调提前把 writeDeferred 置 null 导致 NPE
            withTimeout(3000) { wd.await() }
            offset += chunkSize
            // 块间间隔保证数据发送到空中
            if (offset < pkt.size) delay(80)
        }

        Log.d(TAG, "  -> 写入完成,等待响应...")
        return withTimeout(timeoutMs) { pendingResult!!.await() }
    }

    // ============ 连接蓝牙（带重试） ============
    suspend fun connect(): Boolean {
        Log.d(TAG, "====== connect() =====")
        val adapter = (ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
            ?: throw Exception("蓝牙不可用")
        if (!adapter.isEnabled) throw Exception("请先开启蓝牙")

        val device: BluetoothDevice = try { adapter.getRemoteDevice(LOCK_MAC) }
        catch (e: Exception) { throw Exception("无效的MAC地址: $LOCK_MAC") }

        val maxAttempts = 3
        var lastError: String = "未知错误"

        for (attempt in 1..maxAttempts) {
            Log.d(TAG, "connect 尝试 #$attempt")
            if (attempt > 1) delay(1000L * attempt)

            disconnectGatt()
            resetState()
            connectDeferred = CompletableDeferred()

            val connSuccess = withContext(Dispatchers.Main) {
                gatt = device.connectGatt(ctx, false, gattCallback)
                gatt != null
            }
            if (!connSuccess) { connectDeferred = null; lastError = "无法发起BLE连接"; continue }

            val result = try { withTimeout(10000L) { connectDeferred!!.await() } }
            catch (e: TimeoutCancellationException) { lastError = "连接超时"; continue }

            if (!result) {
                lastError = if (writeChar != null || notifyChar != null) "连接超时" else "服务发现失败"
                refreshGattCache()
                continue
            }

            Log.d(TAG, "connect 成功!")
            return true
        }

        Log.e(TAG, "connect 失败: $lastError")
        throw Exception("连接失败（重试${maxAttempts}次后）: $lastError")
    }

    private fun refreshGattCache() {
        try { gatt?.javaClass?.getMethod("refresh")?.invoke(gatt) } catch (_: Exception) {}
    }

    // ============ 握手 ============
    suspend fun handshake() {
        Log.d(TAG, "====== handshake() =====")
        seq = 0; sessionId = 0; aesKey = AES_KEY; flags = 2; recvBuf.clear()

        val r1 = sendCmd(CMD_GET_SESSION_ID, cmdVer = 12)
        if (r1.status != 1) throw Exception("GET_SESSION_ID失败 status=${r1.status}")
        sessionId = r1.sessionId
        Log.d(TAG, "  GET_SESSION_ID -> sessionId=$sessionId")

        val r2 = sendCmd(CMD_GET_SECRET, cmdVer = 12)
        if (r2.status != 1) throw Exception("GET_SECRET失败 status=${r2.status}")
        if (r2.iterable.size >= 16) aesKey = r2.iterable.copyOf(16)
        Log.d(TAG, "  GET_SECRET -> aesKey更新")

        flags = 3
        val r3 = sendCmd(CMD_GET_AUTH, iterable = AUTH_CODE, cmdVer = 12)
        if (r3.status != 1) throw Exception("鉴权失败 status=${r3.status}")
        Log.d(TAG, "  GET_AUTH -> 鉴权成功")
    }

    // ============ 开锁 ============
    suspend fun unlock(): ResponseData {
        Log.d(TAG, "====== unlock() =====")
        onStatus?.invoke("正在开锁...")

        val now = (System.currentTimeMillis() / 1000).toInt()
        val iterable = ByteArray(15)
        iterable[4] = ((now shr 24) and 0xFF).toByte()
        iterable[5] = ((now shr 16) and 0xFF).toByte()
        iterable[6] = ((now shr 8) and 0xFF).toByte()
        iterable[7] = (now and 0xFF).toByte()
        iterable[8]  = 0; iterable[9]  = 0x01; iterable[10] = 0xE0.toByte()
        iterable[11] = ((now shr 24) and 0xFF).toByte()
        iterable[12] = ((now shr 16) and 0xFF).toByte()
        iterable[13] = ((now shr 8) and 0xFF).toByte()
        iterable[14] = (now and 0xFF).toByte()

        return sendCmd(cmd = CMD_OPEN_LOCK, iterable = iterable, status = 6, flag = 0, cmdVer = 21, timeoutMs = 8000)
    }

    // ============ 预连接 ============
    suspend fun preConnect() {
        Log.d(TAG, "====== preConnect() =====")
        onStatus?.invoke("正在连接门锁...")
        connect()
        onStatus?.invoke("已连接，等待开锁")
    }

    // ============ 一次性开锁闭环 ============
    suspend fun handshakeAndUnlock() {
        Log.d(TAG, "====== handshakeAndUnlock() =====")
        try {
            if (!isConnected) {
                Log.d(TAG, "  isConnected=false -> connect()")
                onStatus?.invoke("连接中...")
                connect()
            } else {
                Log.d(TAG, "  isConnected=true -> 跳过connect")
            }

            Log.d(TAG, "  -> handshake()")
            onStatus?.invoke("握手中...")
            handshake()

            Log.d(TAG, "  -> unlock()")
            val resp = unlock()

            Log.d(TAG, "  -> 响应: status=${resp.status}")
            if (resp.status == 1) {
                val it = resp.iterable
                val power = if (it.isNotEmpty()) (it[0].toInt() and 0xFF).toString() + "%" else "?"
                Log.d(TAG, "  开锁成功! 电量=$power")
                onSuccess?.invoke("开锁成功! 电量=$power")
            } else {
                val errMap = mapOf(0 to "失败", 3 to "远程开锁未开启", 9 to "不允许开锁", 10 to "系统锁定", 40 to "权限过期")
                val errMsg = errMap[resp.status] ?: "错误码${resp.status}"
                Log.e(TAG, "  开锁失败: $errMsg")
                onError?.invoke("开锁失败: $errMsg")
            }
        } catch (e: TimeoutCancellationException) {
            Log.e(TAG, "  TimeoutCancellationException: ${e.message}", e)
            onError?.invoke("开锁命令已发送，门可能已开（未收到确认）")
        } catch (e: CancellationException) {
            Log.w(TAG, "  CancellationException: ${e.message}")
            onStatus?.invoke("已取消")
        } catch (e: Exception) {
            Log.e(TAG, "  Exception: msg=${e.message}", e)
            onError?.invoke(e.message ?: "未知错误")
        } finally {
            Log.d(TAG, "  finally -> disconnectAndClean + cooling 3s")
            disconnectAndClean()
            // 冷却让门锁重置内部状态，然后自动重新预连接
            delay(2000)
            try {
                preConnect()
            } catch (e: CancellationException) {
                // 被新的 unlock/job 打断，正常
            } catch (e: Exception) {
                Log.w(TAG, "  post-unlock reconnect: ${e.message}")
            }
        }
    }

    suspend fun runUnlock() {
        try {
            onStatus?.invoke("正在连接门锁...")
            connect()
            handshakeAndUnlock()
        } catch (e: CancellationException) {
            onStatus?.invoke("已取消")
        } catch (e: Exception) {
            onError?.invoke(e.message ?: "未知错误")
        }
    }

    /** 预连接（异步启动） */
    fun startPreConnect(onStatus: ((String) -> Unit)? = null, onError: ((String) -> Unit)? = null): Job {
        Log.d(TAG, "startPreConnect()")
        killAll()
        this.onStatus = onStatus; this.onError = onError
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        currentJob = scope!!.launch {
            try { preConnect() }
            catch (e: CancellationException) { Log.w(TAG, "preConnect 被取消") }
            catch (e: Exception) { onError?.invoke("预连接失败: ${e.message}") }
        }
        return currentJob!!
    }

    /** 从外部启动开锁流程 */
    fun start(onStatus: ((String) -> Unit)?, onSuccess: ((String) -> Unit)?, onError: ((String) -> Unit)?): Job {
        Log.d(TAG, "start()")
        killAll()
        this.onStatus = onStatus; this.onSuccess = onSuccess; this.onError = onError
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        currentJob = scope!!.launch { handshakeAndUnlock() }
        return currentJob!!
    }

    fun cancel() {
        Log.d(TAG, "cancel()")
        killAll()
    }

    fun disconnect() { disconnectGatt() }

    // ============ 内部辅助 ============
    private fun killAll() {
        Log.d(TAG, "killAll()")
        scope?.cancel()
        scope = null; currentJob = null
        disconnectGatt(); resetState()
    }

    private fun disconnectAndClean() {
        Log.d(TAG, "disconnectAndClean()")
        try {
            failPending("操作取消")
            val d = connectDeferred; connectDeferred = null; d?.complete(false)
            gatt?.disconnect(); gatt?.close(); gatt = null
        } catch (_: Exception) {}
        writeChar = null; notifyChar = null
        needDescriptorWrite = false; descriptorWritten = false
        recvBuf.clear(); pendingSnr = -1; pendingResult = null; writeDeferred = null
    }

    private fun disconnectGatt() {
        Log.d(TAG, "disconnectGatt() gatt=$gatt")
        try {
            failPending("操作取消")
            val d = connectDeferred; connectDeferred = null; d?.complete(false)
            gatt?.disconnect(); gatt?.close(); gatt = null
        } catch (_: Exception) {}
    }

    private fun resetState() {
        sessionId = 0; seq = 0; aesKey = AES_KEY; flags = 2
        writeChar = null; notifyChar = null
        needDescriptorWrite = false; descriptorWritten = false
        recvBuf.clear(); pendingSnr = -1; pendingResult = null; writeDeferred = null
    }
}
