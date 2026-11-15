package io.github.lightjunction.alilogincompat;

import android.content.ContentResolver;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.provider.Settings;
import java.io.File;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

final class TaobaoEnvCompat {
    private static final Set<String> HIDDEN_SETTINGS = new HashSet<>(Arrays.asList(
            "adb_enabled",
            "adb_wifi_enabled",
            "development_settings_enabled"
    ));

    private static final Set<String> HIDDEN_PACKAGES = new HashSet<>(Arrays.asList(
            "io.github.lightjunction.alilogincompat",
            "com.reqable.android",
            "com.guoshi.httpcanary",
            "me.weishu.kernelsu",
            "com.topjohnwu.magisk",
            "org.lsposed.manager",
            "com.reveny.nativecheck",
            "gr.nikolasspyr.integritycheck",
            "bin.mt.plus.canary"
    ));

    private static final String[] HIDDEN_CLASS_PREFIXES = new String[] {
            "de.robv.android.xposed.",
            "org.lsposed.",
            "io.github.lightjunction.alilogincompat.",
            "com.saurik.substrate.",
            "com.elderdrivers."
    };

    private static final Set<String> OBSERVED_KEYS = Collections.synchronizedSet(new HashSet<>());
    private static volatile boolean compatEnabled;
    private static volatile boolean observeEnabled;

    private TaobaoEnvCompat() {}

    static void install(ClassLoader loader, boolean compat, boolean observe) {
        compatEnabled = compat;
        observeEnabled = observe;
        if (!compat && !observe) return;
        hookSettings();
        hookPackageManager(loader);
        hookNetworkInterfaces();
        hookFile();
        XposedBridge.log("AliLoginCompat: TaobaoEnvCompat installed compat=" + compat + " observe=" + observe);
    }

    private static void logOnce(String kind, String value) {
        if (!observeEnabled || value == null) return;
        if (OBSERVED_KEYS.size() >= 256) return;
        String key = kind + ":" + value;
        if (OBSERVED_KEYS.add(key)) {
            XposedBridge.log("AliLoginCompat: [env_trace] " + kind + "=" + value);
        }
    }

    private static boolean isSuspiciousIface(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.startsWith("magicnet") || lower.startsWith("tun") || lower.startsWith("ppp");
    }

    private static void hookNetworkInterfaces() {
        try {
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "getNetworkInterfaces", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    @SuppressWarnings("unchecked")
                    Enumeration<NetworkInterface> orig = (Enumeration<NetworkInterface>) param.getResult();
                    if (orig == null) return;
                    List<NetworkInterface> all = new ArrayList<>();
                    List<NetworkInterface> filtered = new ArrayList<>();
                    while (orig.hasMoreElements()) {
                        NetworkInterface nif = orig.nextElement();
                        if (nif != null) {
                            all.add(nif);
                            if (isSuspiciousIface(nif.getName())) {
                                logOnce("net_iface", nif.getName());
                            } else {
                                filtered.add(nif);
                            }
                        }
                    }
                    param.setResult(Collections.enumeration(compatEnabled ? filtered : all));
                }
            });
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "getByName", String.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args.length >= 1 && param.args[0] instanceof String) {
                        String name = (String) param.args[0];
                        if (isSuspiciousIface(name)) {
                            logOnce("net_getByName", name);
                            if (compatEnabled) param.setResult(null);
                        }
                    }
                }
            });
        } catch (Throwable ignored) {}
    }

    private static boolean isSuspiciousJavaPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("/data/adb") || lower.contains("magisk") ||
               lower.contains("kernelsu") || lower.contains("lsposed") ||
               lower.contains("magicap") || lower.contains("sys-ca-copy") ||
               lower.contains("rescuebrick") || lower.endsWith("/su") ||
               lower.contains("/su/");
    }

    private static void hookFile() {
        try {
            XC_MethodHook fileBoolHook = new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.thisObject instanceof File) {
                        String p = ((File) param.thisObject).getPath();
                        if (isSuspiciousJavaPath(p)) {
                            logOnce("file_check", p);
                            if (compatEnabled) param.setResult(Boolean.FALSE);
                        }
                    }
                }
            };
            XposedHelpers.findAndHookMethod(File.class, "exists", fileBoolHook);
            XposedHelpers.findAndHookMethod(File.class, "canRead", fileBoolHook);
        } catch (Throwable ignored) {}
    }

    private static void hookSettings() {
        XC_MethodHook intHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length >= 2 && param.args[1] instanceof String) {
                    String key = (String) param.args[1];
                    if (HIDDEN_SETTINGS.contains(key)) {
                        logOnce("settings_int", key);
                        if (compatEnabled) param.setResult(0);
                    }
                }
            }
        };
        XC_MethodHook strHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length >= 2 && param.args[1] instanceof String) {
                    String key = (String) param.args[1];
                    if (HIDDEN_SETTINGS.contains(key)) {
                        logOnce("settings_str", key);
                        if (compatEnabled) param.setResult("0");
                    }
                }
            }
        };
        for (Class<?> cls : new Class<?>[] { Settings.Global.class, Settings.Secure.class }) {
            XposedHelpers.findAndHookMethod(cls, "getInt", ContentResolver.class, String.class, intHook);
            XposedHelpers.findAndHookMethod(cls, "getInt", ContentResolver.class, String.class, int.class, intHook);
            XposedHelpers.findAndHookMethod(cls, "getString", ContentResolver.class, String.class, strHook);
        }
    }

    private static void hookPackageManager(ClassLoader loader) {
        Class<?> apm = XposedHelpers.findClassIfExists("android.app.ApplicationPackageManager", loader);
        if (apm == null) return;
        XposedBridge.hookAllMethods(apm, "getInstalledPackages", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Object res = param.getResult();
                if (!(res instanceof List<?>)) return;
                List<?> list = (List<?>) res;
                Iterator<?> it = list.iterator();
                while (it.hasNext()) {
                    Object item = it.next();
                    if (item instanceof PackageInfo) {
                        String pkg = ((PackageInfo) item).packageName;
                        if (HIDDEN_PACKAGES.contains(pkg)) {
                            logOnce("pm_list_pkg", pkg);
                            if (compatEnabled) it.remove();
                        }
                    }
                }
            }
        });
        XposedBridge.hookAllMethods(apm, "getInstalledApplications", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Object res = param.getResult();
                if (!(res instanceof List<?>)) return;
                List<?> list = (List<?>) res;
                Iterator<?> it = list.iterator();
                while (it.hasNext()) {
                    Object item = it.next();
                    if (item instanceof ApplicationInfo) {
                        String pkg = ((ApplicationInfo) item).packageName;
                        if (HIDDEN_PACKAGES.contains(pkg)) {
                            logOnce("pm_list_app", pkg);
                            if (compatEnabled) it.remove();
                        }
                    }
                }
            }
        });
        XC_MethodHook infoHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length >= 1 && param.args[0] instanceof String) {
                    String pkg = (String) param.args[0];
                    if (HIDDEN_PACKAGES.contains(pkg)) {
                        logOnce("pm_query_pkg", pkg);
                        if (compatEnabled) param.setThrowable(new PackageManager.NameNotFoundException(pkg));
                    }
                }
            }
        };
        XposedBridge.hookAllMethods(apm, "getPackageInfo", infoHook);
        XposedBridge.hookAllMethods(apm, "getApplicationInfo", infoHook);
    }

    private static void hookClassForName() {
        XC_MethodHook classHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length >= 1 && param.args[0] instanceof String) {
                    String name = (String) param.args[0];
                    for (String prefix : HIDDEN_CLASS_PREFIXES) {
                        if (name.startsWith(prefix) && !isInternalCaller()) {
                            param.setThrowable(new ClassNotFoundException(name));
                            return;
                        }
                    }
                }
            }
        };
        XposedHelpers.findAndHookMethod(Class.class, "forName", String.class, classHook);
        XposedHelpers.findAndHookMethod(Class.class, "forName", String.class, boolean.class, ClassLoader.class, classHook);
    }

    private static boolean isInternalCaller() {
        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String c = el.getClassName();
            if (c.startsWith("io.github.lightjunction.alilogincompat.") ||
                c.startsWith("de.robv.android.xposed.") ||
                c.startsWith("org.lsposed.")) {
                return true;
            }
        }
        return false;
    }
}
