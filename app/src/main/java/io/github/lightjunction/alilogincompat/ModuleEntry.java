package io.github.lightjunction.alilogincompat;

import android.app.Application;
import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class ModuleEntry implements IXposedHookLoadPackage {
    private static final String ID = "io.github.lightjunction.alilogincompat";
    private static native void configureNative(boolean rewrite, String packageName, boolean probe);
    private static native long[] nativeCounters();
    private static native String nativeRecords();

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam load) {
        if (!(load.packageName.equals("com.taobao.taobao") || load.packageName.equals("com.taobao.idlefish"))) return;
        if (!load.packageName.equals(load.processName)) return;
        try {
            XSharedPreferences prefs = new XSharedPreferences(ID, "policy");
            prefs.reload();
            boolean configured = prefs.contains("rewrite");
            boolean rewrite = configured && prefs.getBoolean("rewrite", false);
            boolean probe = configured && prefs.getBoolean("probe", false);
            System.loadLibrary("alilogincompat");
            configureNative(rewrite, load.packageName, probe);
            XposedBridge.log("AliLoginCompat: loaded package=" + load.packageName + " mode=" + (rewrite ? "rewrite" : "observe") + " configured=" + configured + " probe=" + probe);
            installProbe(load.classLoader, rewrite, probe);
        } catch (Throwable error) {
            XposedBridge.log("AliLoginCompat: initialization failed; original behavior retained: " + error.getClass().getName());
        }
    }

    private void installProbe(ClassLoader loader, boolean rewrite, boolean probe) {
                Thread worker = new Thread(() -> {
                    try {
                        long[] initial = nativeCounters();
                        for (int attempt = 0; attempt < 60 && initial[2] == 0; attempt++) {
                            Thread.sleep(500);
                            initial = nativeCounters();
                        }
                        XposedBridge.log("AliLoginCompat: native status installed=" + (initial[2] != 0) + " matched=" + initial[0] + " rewritten=" + initial[1]);
                        if (!probe) return;
                        Application application = android.app.AndroidAppHelper.currentApplication();
                        if (application == null) throw new IllegalStateException("Application unavailable");
                        Class<?> wrapper = Class.forName("com.ali.user.mobile.security.SecurityGuardManagerWraper", true, loader);
                        Object result = wrapper.getMethod("getWUA").invoke(null);
                        if (result == null) throw new IllegalStateException("No WUA returned");
                        Field field = result.getClass().getField("wua");
                        String wua = (String) field.get(result);
                        long[] counters = nativeCounters();
                        JSONObject record = new JSONObject();
                        record.put("package", application.getPackageName());
                        record.put("local_diagnostic_only", true);
                        record.put("rewrite", rewrite);
                        record.put("matched", counters[0]); record.put("rewritten", counters[1]);
                        record.put("native_profile_installed", counters[2] != 0);
                        record.put("append_calls", counters[3]);
                        record.put("private_native_records_hex", nativeRecords());
                        record.put("wua", wua);
                        File file = new File(application.getCacheDir(), "alilogincompat-probe.json");
                        try (FileOutputStream output = new FileOutputStream(file)) {
                            output.write(record.toString().getBytes(StandardCharsets.UTF_8));
                        }
                        XposedBridge.log("AliLoginCompat: private local diagnostic saved; matched=" + counters[0] + " rewritten=" + counters[1]);
                    } catch (Throwable error) {
                        XposedBridge.log("AliLoginCompat: local diagnostic unavailable: " + error.getClass().getName());
                    }
                }, "AliLoginCompatProbe");
                worker.setDaemon(true); worker.start();
    }
}
