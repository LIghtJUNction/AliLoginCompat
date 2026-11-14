package io.github.lightjunction.alilogincompat;

import android.app.Application;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONObject;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/** Bounded metadata observation; neither command arguments nor results are changed. */
final class SecurityCommandTrace {
    private static final String CLASS = "com.taobao.wireless.security.adapter.JNICLibrary";
    private static final Set<Class<?>> installed = new HashSet<>();
    private static volatile boolean ready;
    private static boolean resolutionFailureLogged;
    private static final ThreadLocal<ArrayList<Integer>> nesting = ThreadLocal.withInitial(ArrayList::new);
    private static final ExecutorService writer = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "AliCommandTraceWriter");
        thread.setDaemon(true);
        return thread;
    });
    private static int count;
    private static boolean written;

    static void install(ClassLoader loader) {
        try { installClass(Class.forName(CLASS, false, loader)); }
        catch (ClassNotFoundException expected) { /* Resolve from the actual SDK proxy instead. */ }
    }

    static synchronized void resolveFromSigner(Object signer) {
        if (ready) return;
        try {
            Field field = signer.getClass().getDeclaredField("f");
            field.setAccessible(true);
            Object proxy = field.get(signer);
            if (proxy == null) return;
            Object handler = Proxy.isProxyClass(proxy.getClass()) ? Proxy.getInvocationHandler(proxy) : proxy;
            try { install(handler.getClass().getClassLoader()); } catch (Throwable ignored) { }
            if (ready) return;
            Class<?> owner = handler.getClass().getEnclosingClass();
            if (owner == null) owner = handler.getClass();
            for (Field candidate : owner.getDeclaredFields()) {
                if (!Modifier.isStatic(candidate.getModifiers()) ||
                        !candidate.getType().getName().equals("com.alibaba.wireless.security.framework.ISecurityGuardPlugin")) continue;
                candidate.setAccessible(true);
                Object plugin = candidate.get(null);
                if (plugin == null) continue;
                Object router = plugin.getClass().getMethod("getRouter").invoke(plugin);
                if (router != null) install(router.getClass().getClassLoader());
                if (ready) return;
            }
            if (!resolutionFailureLogged) {
                resolutionFailureLogged = true;
                XposedBridge.log("AliLoginCompat: command bridge pending; SDK handler=" + handler.getClass().getName());
            }
        } catch (Throwable error) {
            if (!resolutionFailureLogged) {
                resolutionFailureLogged = true;
                XposedBridge.log("AliLoginCompat: command bridge resolution unavailable: " + error.getClass().getName());
            }
        }
    }

    private static synchronized int reserve() { return count < 64 ? ++count : -1; }

    private static synchronized void installClass(Class<?> type) {
        if (!installed.add(type)) return;
        try {
            Method method = type.getDeclaredMethod("doCommandNative", int.class, Object[].class);
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    int command = (Integer) param.args[0];
                    if (command != 20102 && command != 70102 && command != 70103) return;
                    int sequence = reserve();
                    if (sequence < 0) return;
                    try {
                        JSONObject record = new JSONObject();
                        record.put("sequence", sequence);
                        record.put("command", command);
                        record.put("parent_api", BusinessFactorTrace.currentApi());
                        record.put("thread_id", Thread.currentThread().getId());
                        record.put("started_nanos", System.nanoTime());
                        record.put("append_start", BusinessFactorTrace.capturePosition());
                        record.put("parent_commands", new JSONArray(nesting.get()));
                        Object[] args = (Object[]) param.args[1];
                        record.put("argument_count", args == null ? 0 : args.length);
                        if (args != null && command == 20102 && args.length > 5) {
                            if (args[2] instanceof Number) record.put("purpose", args[2]);
                            if (args[5] instanceof Number) record.put("env", args[5]);
                        }
                        if (args != null && command == 70102 && args.length > 8) {
                            if (args[2] instanceof Boolean) record.put("use_wua", args[2]);
                            record.put("input_miniwua_present", args[8] instanceof String && !((String) args[8]).isEmpty());
                        }
                        JSONArray stack = new JSONArray();
                        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
                        for (int i = 0; i < Math.min(frames.length, 24); i++) stack.put(frames[i].toString());
                        record.put("java_stack", stack);
                        nesting.get().add(command);
                        param.setObjectExtra("ali_command_record", record);
                    } catch (Throwable error) {
                        XposedBridge.log("AliLoginCompat: command trace start unavailable: " + error.getClass().getName());
                    }
                }
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Object value = param.getObjectExtra("ali_command_record");
                    if (!(value instanceof JSONObject)) return;
                    try {
                        JSONObject record = (JSONObject) value;
                        record.put("append_end", BusinessFactorTrace.capturePosition());
                        record.put("elapsed_nanos", System.nanoTime() - record.getLong("started_nanos"));
                        Object result = param.getResult();
                        if (result instanceof String) {
                            String text = (String) result;
                            record.put("output_length", text.length());
                            record.put("output_sha256", digest(text));
                        } else if (result instanceof Map) {
                            JSONObject digests = new JSONObject();
                            for (String key : new String[]{"x-sign", "x-mini-wua", "x-sgext", "x-umt"}) {
                                Object field = ((Map<?, ?>) result).get(key);
                                if (field instanceof String) digests.put(key, digest((String) field));
                            }
                            record.put("output_fields_sha256", digests);
                        }
                        if (param.hasThrowable()) record.put("error_class", param.getThrowable().getClass().getName());
                        writer.execute(() -> save(record));
                    } catch (Throwable error) {
                        XposedBridge.log("AliLoginCompat: command trace finish unavailable: " + error.getClass().getName());
                    } finally {
                        ArrayList<Integer> stack = nesting.get();
                        if (!stack.isEmpty()) stack.remove(stack.size() - 1);
                    }
                }
            });
            ready = true;
            XposedBridge.log("AliLoginCompat: bounded security command metadata trace enabled");
        } catch (Throwable error) {
            installed.remove(type);
            XposedBridge.log("AliLoginCompat: command trace hook unavailable: " + error.getClass().getName());
        }
    }

    private static String digest(String value) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder(64);
        for (byte b : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }

    private static void save(JSONObject record) {
        try {
            Application app = android.app.AndroidAppHelper.currentApplication();
            if (app == null) return;
            File file = new File(app.getCacheDir(), "alilogincompat-command-trace.jsonl");
            try (FileOutputStream out = new FileOutputStream(file, written)) {
                out.write((record.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            }
            written = true;
        } catch (Throwable error) {
            XposedBridge.log("AliLoginCompat: command trace write unavailable: " + error.getClass().getName());
        }
    }
}
