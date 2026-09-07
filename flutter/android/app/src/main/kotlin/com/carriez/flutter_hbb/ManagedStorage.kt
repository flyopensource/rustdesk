package com.carriez.flutter_hbb

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings

object ManagedStorage {
    fun ready(context: Context): Boolean {
        if (!BuildConfig.MANAGED_STORAGE) return false
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager()
        if (Build.VERSION.SDK_INT == 29 && !Environment.isExternalStorageLegacy()) return false
        if (Build.VERSION.SDK_INT < 23) return true
        return context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED &&
            context.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    }

    fun root(): String = Environment.getExternalStorageDirectory().absolutePath

    fun request(activity: Activity): Boolean {
        if (!BuildConfig.MANAGED_STORAGE) return false
        return try {
            if (Build.VERSION.SDK_INT >= 30) {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:${activity.packageName}"))
                if (intent.resolveActivity(activity.packageManager) != null) activity.startActivity(intent)
                else activity.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
            } else if (Build.VERSION.SDK_INT >= 23) {
                activity.requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE), 9071)
            }
            true
        } catch (error: Exception) {
            android.util.Log.w("ManagedStorage", "Cannot open storage permission settings", error)
            false
        }
    }
}
