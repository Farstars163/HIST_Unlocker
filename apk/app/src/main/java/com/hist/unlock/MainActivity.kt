package com.hist.unlock

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Job

class MainActivity : ComponentActivity() {

    private val unlocker = HistUnlocker(this)
    private var unlockJob: Job? = null

    // ★ UI 状态
    private val _connectionStatus = androidx.compose.runtime.mutableStateOf("未连接")
    private val _isConnected = androidx.compose.runtime.mutableStateOf(false)
    private val _isRunning = androidx.compose.runtime.mutableStateOf(false)

    // 权限请求
    private val permLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        if (perms.values.all { it }) {
            startPreConnect()
        } else {
            toast("需要蓝牙权限才能使用")
        }
    }

    // 开锁权限请求
    private val unlockPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        if (perms.values.all { it }) {
            startUnlock()
        } else {
            toast("需要蓝牙权限才能使用")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 启动时预连接
        checkPermsAndPreConnect()

        setContent {
            UnlockApp(
                connectionStatus = _connectionStatus.value,
                isConnected = _isConnected.value,
                isRunning = _isRunning.value,
                onUnlock = {
                    _isRunning.value = true
                    checkPermsAndRun()
                },
                onStop  = { stopUnlock() }
            )
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unlocker.cancel()
    }

    // ========== 预连接 ==========
    private fun checkPermsAndPreConnect() {
        val perms = getRequiredPerms()

        val btAdapter = (getSystemService(BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        if (btAdapter == null || !btAdapter.isEnabled) {
            _connectionStatus.value = "请先开启蓝牙"
            return
        }

        if (perms.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }) {
            startPreConnect()
        } else {
            permLauncher.launch(perms.toTypedArray())
        }
    }

    private fun startPreConnect() {
        _connectionStatus.value = "正在连接门锁..."
        unlocker.startPreConnect(
            onStatus = { msg ->
                runOnUiThread {
                    _connectionStatus.value = msg
                    if (msg.contains("等待开锁")) {
                        _isConnected.value = true
                    }
                }
            },
            onError = { msg ->
                runOnUiThread {
                    _connectionStatus.value = "连接失败: $msg"
                    _isConnected.value = false
                }
            }
        )
    }

    // ========== 权限检查（开锁时） ==========
    private fun getRequiredPerms(): List<String> {
        return if (Build.VERSION.SDK_INT >= 31) {
            listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun checkPermsAndRun() {
        val perms = getRequiredPerms()

        val btAdapter = (getSystemService(BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        if (btAdapter == null || !btAdapter.isEnabled) {
            toast("请先开启蓝牙")
            return
        }

        if (perms.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }) {
            startUnlock()
        } else {
            unlockPermLauncher.launch(perms.toTypedArray())
        }
    }

    // ========== 开锁流程 ==========
    private fun startUnlock() {
        _connectionStatus.value = "握手中..."
        _isConnected.value = false

        unlockJob = unlocker.start(
            onStatus  = { msg ->
                runOnUiThread { _connectionStatus.value = msg }
            },
            onSuccess = { msg ->
                runOnUiThread {
                    _isRunning.value = false
                    _connectionStatus.value = "开锁成功"
                    _isConnected.value = false
                    toast("✅ $msg")
                }
            },
            onError   = { msg ->
                runOnUiThread {
                    _isRunning.value = false
                    val status = if (msg.contains("可能已开")) "开锁成功（未确认）" else "开锁失败"
                    _connectionStatus.value = status
                    _isConnected.value = false
                    toast("$msg")
                }
            }
        )
    }

    private fun stopUnlock() {
        unlocker.cancel()
        unlockJob = null
        _isRunning.value = false
        _isConnected.value = false
        _connectionStatus.value = "已停止"
        toast("已停止")
        // 停止后重新预连接
        startPreConnect()
    }

    private fun toast(msg: String) {
        runOnUiThread {
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
        }
    }
}

// ==================== Compose UI ====================
@Composable
fun UnlockApp(
    connectionStatus: String,
    isConnected: Boolean,
    isRunning: Boolean,
    onUnlock: () -> Unit,
    onStop: () -> Unit
) {
    // 开锁按钮脉冲动画
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.04f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "scale"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0xFF0F0C29), Color(0xFF302B63), Color(0xFF24243E))
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        // 背景装饰圆
        Canvas(modifier = Modifier.fillMaxSize()) {
            drawCircle(
                brush = Brush.radialGradient(listOf(Color(0x15FFFFFF), Color.Transparent)),
                radius = size.minDimension * 0.7f,
                center = Offset(size.width / 2, size.height / 2)
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier
                .padding(horizontal = 40.dp)
                .fillMaxWidth()
        ) {
            // 锁图标 - 自定义绘制
            val lockColor = when {
                isRunning   -> Color(0xFFFFD54F)
                isConnected -> Color(0xFF69F0AE)
                else        -> Color(0xFF90A4AE)
            }
            val lockBg = when {
                isRunning   -> Color(0x1AFFD54F)
                isConnected -> Color(0x1A69F0AE)
                else        -> Color(0x1A90A4AE)
            }

            Box(
                modifier = Modifier
                    .size(96.dp)
                    .clip(CircleShape)
                    .background(lockBg),
                contentAlignment = Alignment.Center
            ) {
                Canvas(modifier = Modifier.size(48.dp)) {
                    val c = center
                    val stroke = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                    // 锁梁（弧形）
                    drawArc(
                        color = lockColor,
                        startAngle = 190f, sweepAngle = 160f,
                        useCenter = false, style = stroke,
                        topLeft = Offset(c.x - 14.dp.toPx(), c.y - 22.dp.toPx()),
                        size = androidx.compose.ui.geometry.Size(28.dp.toPx(), 28.dp.toPx())
                    )
                    // 锁体（圆角矩形）
                    val rectPath = Path().apply {
                        addRoundRect(
                            androidx.compose.ui.geometry.RoundRect(
                                left = c.x - 16.dp.toPx(),
                                top = c.y - 6.dp.toPx(),
                                right = c.x + 16.dp.toPx(),
                                bottom = c.y + 18.dp.toPx(),
                                radiusX = 4.dp.toPx(),
                                radiusY = 4.dp.toPx()
                            )
                        )
                    }
                    drawPath(rectPath, color = lockColor, style = stroke)
                    // 钥匙孔
                    drawCircle(color = lockColor, radius = 3.dp.toPx(), center = Offset(c.x, c.y + 4.dp.toPx()))
                    drawLine(color = lockColor, start = Offset(c.x, c.y + 4.dp.toPx()), end = Offset(c.x, c.y + 12.dp.toPx()), strokeWidth = 2.dp.toPx())
                }
            }

            Spacer(Modifier.height(24.dp))

            // 标题
            Text(
                text = "芝麻开门",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White.copy(alpha = 0.95f),
                letterSpacing = 8.sp
            )
            Text(
                text = "快速、便捷",
                fontSize = 14.sp,
                color = Color.White.copy(alpha = 0.45f),
                letterSpacing = 4.sp
            )

            Spacer(Modifier.height(16.dp))

            // 状态指示
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                // 状态点
                val dotColor = when {
                    isRunning   -> Color(0xFFFFD54F)
                    isConnected -> Color(0xFF69F0AE)
                    else        -> Color(0xFF90A4AE)
                }
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(dotColor)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = connectionStatus,
                    fontSize = 13.sp,
                    color = Color.White.copy(alpha = 0.7f),
                    textAlign = TextAlign.Center
                )
            }

            Spacer(Modifier.height(40.dp))

            // 开锁按钮
            Button(
                onClick = { onUnlock() },
                enabled = !isRunning,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isConnected) Color(0xFF69F0AE) else Color(0x6669F0AE),
                    disabledContainerColor = Color(0x3369F0AE)
                ),
                elevation = ButtonDefaults.buttonElevation(
                    defaultElevation = if (isConnected) 8.dp else 2.dp
                )
            ) {
                Text(
                    text = when {
                        isRunning   -> "开锁中..."
                        isConnected -> "一 键 开 锁"
                        else        -> "一 键 开 锁"
                    },
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1B1B2F),
                    letterSpacing = 4.sp
                )
            }

            Spacer(Modifier.height(12.dp))

            // 停止按钮
            AnimatedVisibility(visible = isRunning) {
                OutlinedButton(
                    onClick = { onStop() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White.copy(alpha = 0.6f)
                    ),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = 0.15f))
                ) {
                    Text("取 消 开 锁", fontSize = 14.sp, letterSpacing = 3.sp)
                }
            }

            Spacer(Modifier.height(24.dp))

            // 底部提示
            Text(
                text = "请靠近门锁操作",
                fontSize = 11.sp,
                color = Color.White.copy(alpha = 0.25f),
                letterSpacing = 2.sp
            )
        }
    }
}
