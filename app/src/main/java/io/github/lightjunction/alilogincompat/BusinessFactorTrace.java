package io.github.lightjunction.alilogincompat;

import android.app.Application;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/** Opt-in observation of existing business calls; never initiates a request. */
final class BusinessFactorTrace {
    private static final Set<String> TARGETS = Set.of(
            "mtop.trade.query.bag", "mtop.taobao.detail.batchgetdetail",
            "mtop.taobao.detail.data.get", "mtop.taobao.kosmos.container.login",
            "mtop.relationrecommend.newfacerecommend.recommend",
            "mtop.relationrecommend.wirelessrecommend.recommend",
            "mtop.taobao.wireless.amp2.im.conversation.newrebase");
    private static final Map<String, Integer> counts = new HashMap<>();
    private static final ExecutorService writer = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "AliBusinessTraceWriter");
        thread.setDaemon(true);
        return thread;
    });
    private static boolean written;
    private static final ThreadLocal<String> currentApi = new ThreadLocal<>();
    private static native boolean beginCapture();
    private static native String endCapture();
    static native long capturePosition();
    static String currentApi() { return currentApi.get(); }

    private static synchronized boolean reserve(String api) {
        int count = counts.getOrDefault(api, 0);
        if (count >= 8) return false;
        counts.put(api, count + 1);
        return true;
    }
    private static synchronized void release(String api) {
        counts.put(api, counts.get(api) - 1);
    }

    static void install(ClassLoader loader) throws Exception {
        try { SecurityCommandTrace.install(loader); }
        catch (Throwable error) {
            XposedBridge.log("AliLoginCompat: command trace setup unavailable: " + error.getClass().getName());
        }
        Class<?> signer = Class.forName("tb.n9f", false, loader);
        int installed = 0;
        for (Method method : signer.getDeclaredMethods()) {
            Class<?>[] types = method.getParameterTypes();
            if (!method.getName().equals("r") || types.length != 6
                    || !Map.class.isAssignableFrom(types[0])
                    || !Map.class.isAssignableFrom(method.getReturnType())) continue;
            XposedBridge.hookMethod(method, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        SecurityCommandTrace.resolveFromSigner(param.thisObject);
                        if (!(param.args[0] instanceof Map)) return;
                        Object value = ((Map<?, ?>) param.args[0]).get("api");
                        if (!(value instanceof String) || !TARGETS.contains(value)) return;
                        String api = (String) value;
                        if (!reserve(api)) return;
                        if (!beginCapture()) { release(api); return; }
                        currentApi.set(api);
                        param.setObjectExtra("ali_trace_api", api);
                        param.setObjectExtra("ali_trace_start", System.nanoTime());
                    } catch (Throwable error) {
                        XposedBridge.log("AliLoginCompat: business trace start unavailable: " + error.getClass().getName());
                    }
                }
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Object api = param.getObjectExtra("ali_trace_api");
                    if (api == null) return;
                    try {
                        String nativeData = endCapture();
                        JSONObject record = new JSONObject();
                        record.put("api", api);
                        record.put("thread_id", Thread.currentThread().getId());
                        record.put("elapsed_nanos", System.nanoTime() - (Long) param.getObjectExtra("ali_trace_start"));
                        record.put("native", new JSONObject(nativeData));
                        JSONObject digests = new JSONObject();
                        if (param.getResult() instanceof Map) {
                            Map<?, ?> output = (Map<?, ?>) param.getResult();
                            for (String key : new String[]{"x-sign", "x-mini-wua", "x-sgext", "x-umt"}) {
                                Object value = output.get(key);
                                if (value instanceof String) digests.put(key, sha256((String) value));
                            }
                        }
                        record.put("output_sha256", digests);
                        if (param.hasThrowable()) record.put("error_class", param.getThrowable().getClass().getName());
                        writer.execute(() -> save(record));
                    } catch (Throwable error) {
                        XposedBridge.log("AliLoginCompat: business trace finish unavailable: " + error.getClass().getName());
                    } finally {
                        currentApi.remove();
                    }
                }
            });
            installed++;
        }
        if (installed == 0) throw new NoSuchMethodException("business signer");
        XposedBridge.log("AliLoginCompat: private business trace enabled; results unchanged");
    }

    private static String sha256(String value) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder(64);
        for (byte b : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }

    private static void save(JSONObject record) {
        try {
            Application application = android.app.AndroidAppHelper.currentApplication();
            if (application == null) return;
            File file = new File(application.getCacheDir(), "alilogincompat-business-trace.jsonl");
            try (FileOutputStream output = new FileOutputStream(file, written)) {
                output.write((record.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            }
            written = true;
            XposedBridge.log("AliLoginCompat: private business trace saved");
        } catch (Throwable error) {
            XposedBridge.log("AliLoginCompat: business trace write unavailable: " + error.getClass().getName());
        }
    }
}
