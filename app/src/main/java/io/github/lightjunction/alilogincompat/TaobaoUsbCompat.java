package io.github.lightjunction.alilogincompat;

import android.content.Intent;
import android.content.IntentFilter;
import java.util.concurrent.atomic.AtomicInteger;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

final class TaobaoUsbCompat {
    private static final AtomicInteger LOGGED = new AtomicInteger();

    private TaobaoUsbCompat() {}

    static void install(ClassLoader loader, boolean compat) {
        Class<?> context = XposedHelpers.findClassIfExists("android.app.ContextImpl", loader);
        if (context == null) {
            XposedBridge.log("AliLoginCompat: USB broadcast hook unavailable; original behavior retained");
            return;
        }
        XposedBridge.hookAllMethods(context, "registerReceiver", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                IntentFilter filter = null;
                for (Object argument : param.args) {
                    if (argument instanceof IntentFilter) {
                        filter = (IntentFilter) argument;
                        break;
                    }
                }
                if (filter == null || !UsbCompatPolicy.shouldReplace(
                        "android.hardware.usb.action.USB_STATE", compat)
                        || !filter.hasAction("android.hardware.usb.action.USB_STATE")) return;
                Intent original = (Intent) param.getResult();
                if (original == null) return;
                boolean connected = original.getBooleanExtra("connected", false);
                int sequence = LOGGED.incrementAndGet();
                if (sequence <= 16) {
                    XposedBridge.log("AliLoginCompat: USB broadcast connected=" + connected
                            + " compat=" + compat);
                }
                if (connected) {
                    Intent replacement = new Intent(original);
                    replacement.putExtra("connected", false);
                    param.setResult(replacement);
                }
            }
        });
        XposedBridge.log("AliLoginCompat: USB broadcast hooked compat=" + compat);
    }
}
