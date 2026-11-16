package io.github.lightjunction.alilogincompat;

import android.os.SystemClock;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/** Java response observation only. No network, security-factor generation, or native hooks. */
final class MtopStatusTrace {
    private static final MtopStatusPolicy POLICY = new MtopStatusPolicy();
    private static final ThreadLocal<Boolean> OBSERVING = new ThreadLocal<>();
    private static boolean installed;

    private MtopStatusTrace() {}

    static synchronized void install(ClassLoader loader) {
        if (installed) return;
        final Class<?> responseClass = XposedHelpers.findClass("mtopsdk.mtop.domain.MtopResponse", loader);
        final Reader reader = new Reader(responseClass);
        XposedBridge.hookMethod(reader.retGetter, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (!param.hasThrowable()) {
                    reader.observe(param.thisObject, MtopStatusPolicy.Stage.RET_READ, param.getResult());
                }
            }
        });
        installed = true;

        boolean filterEntry = false;
        try {
            Class<?> contextClass = XposedHelpers.findClass("tb.w4j", loader);
            final Field responseField = XposedHelpers.findField(contextClass, "c");
            Class<?> filterClass = XposedHelpers.findClass("tb.ev8", loader);
            XposedHelpers.findAndHookMethod(filterClass, "c", contextClass, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args.length == 1 && param.args[0] != null) {
                            reader.observe(responseField.get(param.args[0]), MtopStatusPolicy.Stage.FILTER_ENTRY, null);
                        }
                    } catch (Throwable ignored) {
                        // Observation must never replace a filter result or exception.
                    }
                }
            });
            filterEntry = true;
        } catch (Throwable ignored) {
            // Ret-code observation remains useful when a version changes the internal filter.
        }
        XposedBridge.log("AliLoginCompat: status trace ready filter_entry=" + filterEntry
                + " limit=" + MtopStatusPolicy.MAX_RECORDS + " native=false");
    }

    private static final class Reader {
        final Class<?> responseClass;
        final Method apiGetter, httpGetter, retGetter;

        Reader(Class<?> responseClass) {
            this.responseClass = responseClass;
            apiGetter = XposedHelpers.findMethodExact(responseClass, "getApi");
            httpGetter = XposedHelpers.findMethodExact(responseClass, "getResponseCode");
            retGetter = XposedHelpers.findMethodExact(responseClass, "getRetCode");
        }

        void observe(Object response, MtopStatusPolicy.Stage stage, Object returnedCode) {
            try {
                if (Boolean.TRUE.equals(OBSERVING.get()) || POLICY.isFull()
                        || response == null || !responseClass.isInstance(response)) return;
                OBSERVING.set(Boolean.TRUE);
                try {
                    // Read existing response state; bypass getter hooks to avoid recursive events.
                    Object api = XposedBridge.invokeOriginalMethod(apiGetter, response, new Object[0]);
                    Object http = XposedBridge.invokeOriginalMethod(httpGetter, response, new Object[0]);
                    Object ret = stage == MtopStatusPolicy.Stage.RET_READ ? returnedCode
                            : XposedBridge.invokeOriginalMethod(retGetter, response, new Object[0]);
                    if (!(http instanceof Integer)) return;
                    String record = POLICY.record(response, stage, SystemClock.elapsedRealtime(),
                            api instanceof String ? (String) api : null, (Integer) http,
                            ret instanceof String ? (String) ret : null);
                    if (record != null) XposedBridge.log("AliLoginCompat: MTOP_STATUS " + record);
                } finally {
                    OBSERVING.remove();
                }
            } catch (Throwable ignored) {
                // No arbitrary error text or stack is logged; original application behavior continues.
            }
        }
    }
}
