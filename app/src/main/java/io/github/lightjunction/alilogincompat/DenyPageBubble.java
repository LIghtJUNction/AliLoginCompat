package io.github.lightjunction.alilogincompat;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;
import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import de.robv.android.xposed.XC_MethodHook;
import android.content.res.XModuleResources;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

final class DenyPageBubble {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static WeakReference<Activity> foreground = new WeakReference<>(null);
    private static WindowManager manager;
    private static View bubble;
    private static boolean receivedDeny, dismissed;
    private static int positionX = -1, positionY = -1;
    private static String modulePath;
    private static long dismissEpoch;
    private static final AtomicInteger folded = new AtomicInteger();

    static void install(ClassLoader loader, String apkPath, long epoch) {
        // Validate the original failure machinery before suppressing any UI.
        Class<?> handlerClass = XposedHelpers.findClass("mtopsdk.mtop.antiattack.AntiAttackHandlerImpl", loader);
        XposedHelpers.findField(handlerClass, "handler");
        XposedHelpers.findField(handlerClass, "timeoutRunnable");
        XposedHelpers.findField(handlerClass, "isHandling");
        Class<?> switches = XposedHelpers.findClass("mtopsdk.mtop.global.SwitchConfig", loader);
        Class<?> broadcasts = XposedHelpers.findClass("com.alibaba.wireless.security.open.middletier.fc.ui.LocalBroadcastManager", loader);
        Class<?> bridge = XposedHelpers.findClass("com.alibaba.wireless.security.open.middletier.fc.ui.IUIBridge", loader);
        String createAction = (String) XposedHelpers.getStaticObjectField(bridge, "INTENT_ACTIVITY_CREATE");
        String resultAction = (String) XposedHelpers.getStaticObjectField(bridge, "INTENT_ACTIVITY_RESULT");
        String sessionKey = (String) XposedHelpers.getStaticObjectField(bridge, "KEY_SESSION_ID");
        String resultKey = (String) XposedHelpers.getStaticObjectField(bridge, "KEY_UI_RESULT");
        String sampleKey = (String) XposedHelpers.getStaticObjectField(bridge, "KEY_IS_SAMPLE");
        modulePath = apkPath;
        dismissEpoch = epoch;
        XposedHelpers.findAndHookMethod(Instrumentation.class, "callActivityOnResume", Activity.class, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Activity activity = (Activity) param.args[0];
                foreground = new WeakReference<>(activity);
                if (receivedDeny && !dismissed) show(activity);
            }
        });
        XposedHelpers.findAndHookMethod(Instrumentation.class, "callActivityOnPause", Activity.class, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (foreground.get() == param.args[0]) {
                    remove();
                    foreground.clear();
                }
            }
        });
        XposedBridge.hookAllMethods(Instrumentation.class, "execStartActivity", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                Intent intent = null;
                Context context = null;
                for (Object argument : param.args) {
                    if (argument instanceof Intent) intent = (Intent) argument;
                    if (context == null && argument instanceof Context) context = (Context) argument;
                }
                if (intent == null || context == null || intent.getComponent() == null) return;
                String target = intent.getComponent().getClassName();
                if (!(target.equals("com.alibaba.wireless.security.open.middletier.fc.ui.ContainerActivity")
                        || target.equals("com.alibaba.wireless.security.open.middletier.fc.ui.ExtContainerActivity")
                        || target.equals("com.alibaba.wireless.security.open.middletier.fc.ui.Ext2ContainerActivity"))) return;
                if (!DenyLocationPolicy.shouldReplace(intent.getStringExtra("location"))) return;
                long session = intent.getLongExtra("sessionId", 0L);
                if (session == 0) return;
                try {
                    Object bus = XposedHelpers.callStaticMethod(broadcasts, "getInstance", context);
                    Intent created = new Intent(createAction).setPackage(context.getPackageName());
                    created.putExtra(sessionKey, session).putExtra(resultKey, 1).putExtra(sampleKey, intent.getBooleanExtra("isSample", false));
                    Intent cancelled = new Intent(resultAction).setPackage(context.getPackageName());
                    cancelled.putExtra(sessionKey, session).putExtra(resultKey, 4).putExtra(sampleKey, intent.getBooleanExtra("isSample", false));
                    // Acknowledge the replacement UI on CREATE, then send CANCEL=4
                    // on RESULT, exactly as closing the original container does.
                    if (!(Boolean) XposedHelpers.callMethod(bus, "sendBroadcast", created)) return;
                    if (!(Boolean) XposedHelpers.callMethod(bus, "sendBroadcast", cancelled)) return;
                    param.setResult(null);
                    notifyDeny();
                    int count = folded.incrementAndGet();
                    if (count <= 8 || count % 100 == 0) XposedBridge.log("AliLoginCompat: SDK deny launch folded count=" + count + "; original CANCEL callback delivered");
                    if (count == 1) {
                        StringBuilder trace = new StringBuilder("AliLoginCompat: SDK deny launch stack");
                        StackTraceElement[] stack = new Throwable().getStackTrace();
                        for (StackTraceElement frame : stack) trace.append("\n  ").append(frame);
                        XposedBridge.log(trace.toString());
                    }
                } catch (Throwable unavailable) {
                    XposedBridge.log("AliLoginCompat: SDK deny UI fallback: " + unavailable.getClass().getName());
                }
            }
        });
        XposedHelpers.findAndHookMethod(handlerClass, "handle", String.class, String.class, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (!DenyLocationPolicy.shouldReplace((String) param.args[0])) return;
                AtomicBoolean handling = null;
                boolean acquired = false;
                try {
                    Handler originalHandler = (Handler) XposedHelpers.getObjectField(param.thisObject, "handler");
                    Runnable originalFailure = (Runnable) XposedHelpers.getObjectField(param.thisObject, "timeoutRunnable");
                    handling = (AtomicBoolean) XposedHelpers.getObjectField(param.thisObject, "isHandling");
                    if (originalHandler == null || originalFailure == null || handling == null) return;
                    acquired = handling.compareAndSet(false, true);
                    if (acquired) {
                        Object config = XposedHelpers.callStaticMethod(switches, "getInstance");
                        long seconds = ((Number) XposedHelpers.callMethod(config, "getGlobalAttackAttackWaitInterval")).longValue();
                        long delay = seconds > 0 ? Math.multiplyExact(seconds, 1000L) : 20000L;
                        // The caller adds its request to ANTI after handle returns.
                        // Retain the original delayed failure, never report verification success.
                        if (!originalHandler.postDelayed(originalFailure, delay)) {
                            handling.set(false);
                            return;
                        }
                    }
                    param.setResult(null);
                    notifyDeny();
                    int count = folded.incrementAndGet();
                    if (count <= 8 || count % 100 == 0) XposedBridge.log("AliLoginCompat: deny page folded count=" + count + "; original failure handling retained");
                } catch (Throwable unavailable) {
                    if (acquired && handling != null) handling.set(false);
                    XposedBridge.log("AliLoginCompat: deny UI fallback: " + unavailable.getClass().getName());
                }
            }
        });
        XposedBridge.log("AliLoginCompat: nonmodal deny bubble enabled");
    }

    private static void notifyDeny() {
        MAIN.post(() -> {
            receivedDeny = true;
            Activity activity = foreground.get();
            if (activity != null && !dismissed) show(activity);
        });
    }

    private static Resources resources(Activity activity) throws Exception {
        try {
            return activity.createPackageContext("io.github.lightjunction.alilogincompat", Context.CONTEXT_IGNORE_SECURITY).getResources();
        } catch (Exception hidden) {
            if (modulePath == null) throw hidden;
            return XModuleResources.createInstance(modulePath, null);
        }
    }

    private static void show(Activity activity) {
        if (dismissed || activity.isFinishing() || activity.isDestroyed()) return;
        if (activity.getSharedPreferences("alilogincompat_ui", Context.MODE_PRIVATE)
                .getLong("dismissed_epoch", Long.MIN_VALUE) == dismissEpoch) {
            dismissed = true;
            return;
        }
        // Repeated server rejections must not detach a button during a touch.
        if (bubble != null) return;
        View decor = activity.getWindow().getDecorView();
        if (decor.getWindowToken() == null) {
            decor.post(() -> { if (foreground.get() == activity && receivedDeny && !dismissed) show(activity); });
            return;
        }
        remove();
        try {
            Resources strings = resources(activity);
            int width = dp(activity, 44), height = dp(activity, 42);
            FrameLayout root = new FrameLayout(activity);
            root.setAlpha(0.72f);
            TextView dot = new TextView(activity);
            dot.setText(strings.getString(R.string.deny_ball_symbol));
            dot.setTextColor(Color.WHITE); dot.setTextSize(15); dot.setGravity(Gravity.CENTER);
            dot.setContentDescription(strings.getString(R.string.deny_ball_hint));
            GradientDrawable circle = new GradientDrawable();
            circle.setShape(GradientDrawable.OVAL); circle.setColor(0xff607d8b);
            dot.setBackground(circle);
            FrameLayout.LayoutParams dotSize = new FrameLayout.LayoutParams(dp(activity, 28), dp(activity, 28), Gravity.START | Gravity.BOTTOM);
            root.addView(dot, dotSize);
            TextView close = new TextView(activity);
            close.setText(strings.getString(R.string.deny_ball_close));
            close.setTextColor(Color.DKGRAY); close.setTextSize(16); close.setGravity(Gravity.CENTER);
            close.setContentDescription(strings.getString(R.string.deny_ball_close_hint));
            root.addView(close, new FrameLayout.LayoutParams(dp(activity, 24), dp(activity, 24), Gravity.END | Gravity.TOP));
            close.setOnClickListener(view -> {
                dismissed = true;
                remove();
                try {
                    activity.getSharedPreferences("alilogincompat_ui", Context.MODE_PRIVATE)
                            .edit().putLong("dismissed_epoch", dismissEpoch).commit();
                } catch (RuntimeException unavailable) {
                    XposedBridge.log("AliLoginCompat: persistent bubble dismissal unavailable");
                }
                XposedBridge.log("AliLoginCompat: deny bubble dismissed");
            });
            WindowManager wm = activity.getWindowManager();
            WindowManager.LayoutParams params = new WindowManager.LayoutParams(width, height,
                    WindowManager.LayoutParams.TYPE_APPLICATION_PANEL,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                    PixelFormat.TRANSLUCENT);
            params.token = activity.getWindow().getDecorView().getWindowToken();
            params.setTitle("AliLoginCompat.DenyBubble");
            params.gravity = Gravity.TOP | Gravity.START;
            int screenWidth = activity.getResources().getDisplayMetrics().widthPixels;
            int screenHeight = activity.getResources().getDisplayMetrics().heightPixels;
            params.x = positionX >= 0 ? Math.min(positionX, screenWidth - width) : screenWidth - width - dp(activity, 6);
            params.y = positionY >= 0 ? Math.min(positionY, screenHeight - height) : screenHeight / 2;
            dot.setOnTouchListener(new View.OnTouchListener() {
                float downX, downY; int startX, startY; boolean moved;
                @Override public boolean onTouch(View view, MotionEvent event) {
                    switch (event.getActionMasked()) {
                        case MotionEvent.ACTION_DOWN:
                            downX = event.getRawX(); downY = event.getRawY(); startX = params.x; startY = params.y; moved = false;
                            return true;
                        case MotionEvent.ACTION_MOVE:
                            float dx = event.getRawX() - downX, dy = event.getRawY() - downY;
                            moved |= Math.abs(dx) + Math.abs(dy) > dp(activity, 5);
                            params.x = Math.max(0, Math.min(screenWidth - width, startX + (int) dx));
                            params.y = Math.max(0, Math.min(screenHeight - height, startY + (int) dy));
                            positionX = params.x; positionY = params.y;
                            if (bubble == root) {
                                try { wm.updateViewLayout(root, params); } catch (RuntimeException detached) { remove(); }
                            }
                            return true;
                        case MotionEvent.ACTION_UP:
                            if (!moved) { view.performClick(); Toast.makeText(activity, strings.getString(R.string.deny_ball_hint), Toast.LENGTH_SHORT).show(); }
                            return true;
                        default: return true;
                    }
                }
            });
            manager = wm; bubble = root;
            wm.addView(root, params);
        } catch (Throwable unavailable) {
            remove();
            XposedBridge.log("AliLoginCompat: bubble unavailable: " + unavailable.getClass().getName());
        }
    }

    private static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }
    private static void remove() {
        View previous = bubble; WindowManager previousManager = manager;
        bubble = null; manager = null;
        if (previous != null && previousManager != null) {
            try { previousManager.removeViewImmediate(previous); } catch (RuntimeException ignored) { }
        }
    }
}
