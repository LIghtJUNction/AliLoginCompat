package io.github.lightjunction.alilogincompat;

import android.app.Application;
import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class ModuleEntry implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private static final String ID = "io.github.lightjunction.alilogincompat";
    private static String modulePath;
    @Override public void initZygote(StartupParam startup) { modulePath = startup.modulePath; }
    private static native void configureNative(boolean rewrite, String packageName, boolean probe, boolean envCompat, boolean envTrace, boolean traceBusiness);
    private static native long[] nativeCounters();
    private static native String nativeRecords();

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam load) {
        if (!(load.packageName.equals("com.taobao.taobao") || load.packageName.equals("com.taobao.idlefish"))) return;
        if (!load.packageName.equals(load.processName)) return;
        try {
            XSharedPreferences prefs = new XSharedPreferences(ID, "policy");
            prefs.reload();
            boolean configured = prefs.contains("rewrite");
            boolean rewrite = configured && (load.packageName.equals("com.taobao.taobao")
                    ? prefs.getBoolean("rewrite_taobao", false)
                    : prefs.getBoolean("rewrite", false));
            boolean probe = configured && prefs.getBoolean("probe", false);
            boolean trace = configured && load.packageName.equals("com.taobao.taobao") && prefs.getBoolean("trace_business", false);
            boolean statusTrace = configured && load.packageName.equals("com.taobao.taobao") && prefs.getBoolean("trace_status", false);
            boolean envCompat = configured && load.packageName.equals("com.taobao.taobao") && prefs.getBoolean("env_compat", false);
            boolean envTrace = configured && load.packageName.equals("com.taobao.taobao") && prefs.getBoolean("env_trace", false);
            if (statusTrace) {
                try { MtopStatusTrace.install(load.classLoader); }
                catch (Throwable unavailable) { XposedBridge.log("AliLoginCompat: status trace unavailable; original behavior retained"); }
            }
            if (load.packageName.equals("com.taobao.taobao") && prefs.getBoolean("deny_bubble", true)) {
                try { DenyPageBubble.install(load.classLoader, modulePath, prefs.getLong("deny_bubble_epoch", 0L)); }
                catch (Throwable unavailable) { XposedBridge.log("AliLoginCompat: deny bubble hook unavailable: " + unavailable.getClass().getName()); }
            }
            if (!rewrite && !probe && !trace && !envCompat && !envTrace) {
                XposedBridge.log("AliLoginCompat: loaded package=" + load.packageName + " mode=ui-only native_hooks=skipped configured=" + configured + " probe=false status_trace=" + statusTrace);
                return;
            }
            System.loadLibrary("alilogincompat");
            configureNative(rewrite, load.packageName, probe, envCompat, envTrace, trace);
            if (load.packageName.equals("com.taobao.taobao") && (envCompat || envTrace)) {
                try { TaobaoEnvCompat.install(load.classLoader, envCompat, envTrace); }
                catch (Throwable unavailable) { XposedBridge.log("AliLoginCompat: taobao env compat unavailable: " + unavailable.getClass().getName()); }
            }
            if (trace) {
                try { BusinessFactorTrace.install(load.classLoader); }
                catch (Throwable unavailable) { XposedBridge.log("AliLoginCompat: business trace hook unavailable: " + unavailable.getClass().getName()); }
            }
            XposedBridge.log("AliLoginCompat: loaded package=" + load.packageName + " mode=" + (rewrite ? "rewrite" : "observe") + " configured=" + configured + " probe=" + probe + " env_compat=" + envCompat + " env_trace=" + envTrace);
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
                if (application.getPackageName().equals("com.taobao.taobao")) {
                    JSONObject mini = new JSONObject();
                    try {
                        Class<?> api = Class.forName("com.alibaba.wireless.security.open.securitybody.ISecurityBodyComponent", true, loader);
                        Object manager = wrapper.getMethod("getSecurityGuardManager").invoke(null);
                        Object component = manager.getClass().getMethod("getInterface", Class.class).invoke(manager, api);
                        Class<?> environment = Class.forName("com.ali.user.mobile.utils.EnvUtil", true, loader);
                        int env = (Integer) environment.getMethod("getAlimmsdk_env").invoke(null);
                        java.lang.reflect.Method generate = api.getMethod("getSecurityBodyDataEx", String.class, String.class, String.class, java.util.HashMap.class, int.class, int.class);
                        long[] before = nativeCounters();
                        Object first = generate.invoke(component, null, null, null, null, 8, env);
                        long[] middle = nativeCounters();
                        Object second = generate.invoke(component, null, null, null, null, 8, env);
                        long[] after = nativeCounters();
                        mini.put("purpose", 8); mini.put("environment", env);
                        mini.put("first", first); mini.put("second", second);
                        mini.put("first_append_delta", middle[3] - before[3]);
                        mini.put("second_append_delta", after[3] - middle[3]);
                        mini.put("first_matched_delta", middle[0] - before[0]);
                        mini.put("second_matched_delta", after[0] - middle[0]);
                        mini.put("first_rewritten_delta", middle[1] - before[1]);
                        mini.put("second_rewritten_delta", after[1] - middle[1]);
                    } catch (Throwable unavailable) {
                        mini.put("error_class", unavailable.getClass().getName());
                        if (unavailable.getCause() != null) mini.put("cause_class", unavailable.getCause().getClass().getName());
                    }
                    record.put("miniwua_diagnostic", mini);
                }
                record.put("private_native_records_hex", nativeRecords());
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
