package top.llklkl.authenticatorvault

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : FlutterFragmentActivity() {
    private val securityBridge by lazy { AndroidSecurityBridge(this) }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        securityBridge.attach(flutterEngine)
    }

    override fun onDestroy() {
        securityBridge.detach()
        super.onDestroy()
    }
}

private class AndroidSecurityBridge(private val activity: MainActivity) {
    companion object {
        private const val METHOD_CHANNEL = "top.llklkl.authenticatorvault/security"
        private const val EVENT_CHANNEL = "top.llklkl.authenticatorvault/security_events"
        private const val KEY_ALIAS = "top.llklkl.authenticatorvault.quick_unlock.v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val MAGIC = byteArrayOf(0x41, 0x56, 0x4b, 0x53) // AVKS
        private val AAD = "top.llklkl.authenticatorvault/android-keyring/v1".toByteArray()
    }

    private val atomicFile = AtomicFile(activity.noBackupFilesDir.resolve("quick-unlock-keyring.v1"))
    private val promptActive = AtomicBoolean(false)
    private var eventSink: EventChannel.EventSink? = null
    private var receiverRegistered = false
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) eventSink?.success("screenOff")
        }
    }

    fun attach(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "canAuthenticateStrong" -> result.success(canAuthenticateStrong())
                    "hasKeyring" -> result.success(atomicFile.baseFile.isFile)
                    "sealKeyring" -> {
                        val bytes = call.arguments as? ByteArray
                        if (bytes == null || bytes.isEmpty()) {
                            result.error("invalidInput", null, null)
                        } else {
                            seal(bytes, result)
                        }
                    }
                    "unsealKeyring" -> unseal(result)
                    "clearKeyring" -> {
                        clearKeyring()
                        result.success(null)
                    }
                    "setContentProtected" -> {
                        setContentProtected(call.arguments == true)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
        EventChannel(engine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    eventSink = events
                    registerScreenReceiver()
                }

                override fun onCancel(arguments: Any?) {
                    eventSink = null
                    unregisterScreenReceiver()
                }
            })
    }

    fun detach() {
        eventSink = null
        unregisterScreenReceiver()
    }

    private fun canAuthenticateStrong(): Boolean =
        BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private fun seal(cleartext: ByteArray, result: MethodChannel.Result) {
        runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(AAD)
            authenticate(cipher, result, cleanup = { cleartext.fill(0) }) { authenticated ->
                val encrypted = authenticated.doFinal(cleartext)
                val encoded = MAGIC + byteArrayOf(1, authenticated.iv.size.toByte()) +
                    authenticated.iv + encrypted
                val output = atomicFile.startWrite()
                try {
                    output.write(encoded)
                    output.fd.sync()
                    atomicFile.finishWrite(output)
                } catch (error: Throwable) {
                    atomicFile.failWrite(output)
                    throw error
                }
                byteArrayOf()
            }
        }.onFailure {
            cleartext.fill(0)
            reportCryptoFailure(it, result)
        }
    }

    private fun unseal(result: MethodChannel.Result) {
        runCatching {
            val encoded = atomicFile.readFully()
            if (encoded.size < 6 || !encoded.copyOfRange(0, 4).contentEquals(MAGIC) || encoded[4] != 1.toByte()) {
                throw IllegalStateException("invalid sealed keyring")
            }
            val ivSize = encoded[5].toInt() and 0xff
            if (ivSize != 12 || encoded.size <= 6 + ivSize) throw IllegalStateException("invalid sealed keyring")
            val iv = encoded.copyOfRange(6, 6 + ivSize)
            val ciphertext = encoded.copyOfRange(6 + ivSize, encoded.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(128, iv))
            cipher.updateAAD(AAD)
            authenticate(cipher, result) { authenticated -> authenticated.doFinal(ciphertext) }
        }.onFailure { reportCryptoFailure(it, result) }
    }

    private fun authenticate(
        cipher: Cipher,
        result: MethodChannel.Result,
        cleanup: () -> Unit = {},
        operation: (Cipher) -> ByteArray,
    ) {
        if (!promptActive.compareAndSet(false, true)) {
            cleanup()
            result.error("busy", null, null)
            return
        }
        val prompt = BiometricPrompt(
            activity,
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(value: BiometricPrompt.AuthenticationResult) {
                    promptActive.set(false)
                    val outcome = runCatching {
                        val authenticated = value.cryptoObject?.cipher
                            ?: throw IllegalStateException("missing crypto object")
                        operation(authenticated)
                    }
                    cleanup()
                    outcome.onSuccess { bytes ->
                        if (bytes.isEmpty()) result.success(null) else result.success(bytes)
                    }.onFailure { reportCryptoFailure(it, result) }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    promptActive.set(false)
                    cleanup()
                    val code = when (errorCode) {
                        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "lockout"
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_CANCELED -> "cancelled"
                        else -> "notAvailable"
                    }
                    result.error(code, null, null)
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("验证身份")
            .setSubtitle("使用强生物识别解锁工作区")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("取消")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun existingKey(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return store.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw KeyPermanentlyInvalidatedException()
    }

    private fun reportCryptoFailure(error: Throwable, result: MethodChannel.Result) {
        promptActive.set(false)
        val invalidated = error is KeyPermanentlyInvalidatedException ||
            error.cause is KeyPermanentlyInvalidatedException
        if (invalidated) clearKeyring()
        result.error(if (invalidated) "keyInvalidated" else "storageFailure", null, null)
    }

    private fun clearKeyring() {
        atomicFile.delete()
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null); deleteEntry(KEY_ALIAS) }
        }
    }

    private fun setContentProtected(enabled: Boolean) {
        if (enabled) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        activity.window.decorView.filterTouchesWhenObscured = enabled
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            activity.window.setHideOverlayWindows(enabled)
        }
    }

    private fun registerScreenReceiver() {
        if (receiverRegistered) return
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.registerReceiver(screenOffReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            activity.registerReceiver(screenOffReceiver, filter)
        }
        receiverRegistered = true
    }

    private fun unregisterScreenReceiver() {
        if (!receiverRegistered) return
        activity.unregisterReceiver(screenOffReceiver)
        receiverRegistered = false
    }
}
