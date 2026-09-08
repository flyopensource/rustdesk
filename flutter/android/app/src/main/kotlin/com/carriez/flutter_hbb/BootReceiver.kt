package com.carriez.flutter_hbb

import android.Manifest.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
import android.Manifest.permission.SYSTEM_ALERT_WINDOW
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.Toast
import com.hjq.permissions.XXPermissions
import io.flutter.embedding.android.FlutterActivity

const val DEBUG_BOOT_COMPLETED = "com.carriez.flutter_hbb.DEBUG_BOOT_COMPLETED"
private const val QUICKBOOT_POWERON = "android.intent.action.QUICKBOOT_POWERON"

class BootReceiver : BroadcastReceiver() {
    private val logTag = "tagBootReceiver"

    private fun applyUnattendedRootPolicy(context: Context): Boolean {
        val prefs = context.getSharedPreferences(KEY_SHARED_PREFERENCES, FlutterActivity.MODE_PRIVATE)
        val command = prefs.getString(KEY_UNATTENDED_ROOT_COMMAND, "") ?: ""
        if (command.isEmpty() || command.length > 255 || command == "disabled" ||
            command.any { it.isWhitespace() || it.isISOControl() }) return false
        val policy = buildString {
            append("input keyevent KEYCODE_WAKEUP")
            if (BuildConfig.MANAGED_STORAGE) {
                if (Build.VERSION.SDK_INT >= 30) {
                    append(" && appops set --uid ${context.packageName} MANAGE_EXTERNAL_STORAGE allow")
                } else if (Build.VERSION.SDK_INT >= 23) {
                    append(" && pm grant ${context.packageName} android.permission.READ_EXTERNAL_STORAGE")
                    append(" && pm grant ${context.packageName} android.permission.WRITE_EXTERNAL_STORAGE")
                }
            }
            append(" && appops set ${context.packageName} SYSTEM_ALERT_WINDOW allow")
            append(" && dumpsys deviceidle whitelist +${context.packageName}")
        }
        val commandLine = when (prefs.getString(KEY_UNATTENDED_ROOT_STYLE, "")) {
            "DASH_C" -> listOf(command, "-c", policy)
            "UID_SHELL" -> listOf(command, "0", "sh", "-c", policy)
            else -> return false
        }
        val process = try {
            ProcessBuilder(commandLine).redirectErrorStream(true).start()
        } catch (error: Exception) {
            Log.w(logTag, "Cannot execute unattended root policy", error)
            return false
        }
        val deadline = System.currentTimeMillis() + 3000
        while (System.currentTimeMillis() < deadline) {
            try {
                return process.exitValue() == 0
            } catch (_: IllegalThreadStateException) {
                Thread.sleep(50)
            }
        }
        process.destroy()
        return false
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(logTag, "onReceive ${intent.action}")

        if (Intent.ACTION_BOOT_COMPLETED == intent.action || QUICKBOOT_POWERON == intent.action ||
            DEBUG_BOOT_COMPLETED == intent.action) {
            // check SharedPreferences config
            val prefs = context.getSharedPreferences(KEY_SHARED_PREFERENCES, FlutterActivity.MODE_PRIVATE)
            if (!prefs.getBoolean(KEY_START_ON_BOOT_OPT, false)) {
                Log.d(logTag, "KEY_START_ON_BOOT_OPT is false")
                return
            }
            Log.d(logTag, "unattended root policy applied: ${applyUnattendedRootPolicy(context)}")
            // check pre-permission
            if (!XXPermissions.isGranted(context, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, SYSTEM_ALERT_WINDOW)){
                Log.w(logTag, "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS or SYSTEM_ALERT_WINDOW is not granted")
            }

            val it = Intent(context, MainService::class.java).apply {
                action = ACT_INIT_MEDIA_PROJECTION_AND_SERVICE
                putExtra(EXT_INIT_FROM_BOOT, true)
            }
            Toast.makeText(context, "RustDesk is Open", Toast.LENGTH_LONG).show()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(it)
            } else {
                context.startService(it)
            }
        }
    }
}
