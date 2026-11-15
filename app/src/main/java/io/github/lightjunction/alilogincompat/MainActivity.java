package io.github.lightjunction.alilogincompat;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().getDecorView().setSystemUiVisibility(android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | android.view.View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        ScrollView scroll = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        scroll.addView(layout);
        setContentView(scroll);
        text(layout, R.string.title, 24);
        text(layout, R.string.description, 16);
        final SharedPreferences preferences;
        try {
            @SuppressWarnings("deprecation") SharedPreferences value = getSharedPreferences("policy", MODE_WORLD_READABLE);
            preferences = value;
            if (!preferences.contains("rewrite")) preferences.edit().putBoolean("rewrite", true).putBoolean("probe", false).commit();
        } catch (SecurityException unavailable) {
            text(layout, R.string.prefs_unavailable, 18);
            return;
        }
        toggle(layout, preferences, "rewrite", R.string.rewrite, true);
        toggle(layout, preferences, "rewrite_taobao", R.string.rewrite_taobao, false);
        toggle(layout, preferences, "deny_bubble", R.string.deny_bubble, true);
        text(layout, R.string.deny_bubble_note, 14);
        toggle(layout, preferences, "probe", R.string.probe, false);
        toggle(layout, preferences, "trace_business", R.string.trace_business, false);
        text(layout, R.string.trace_business_note, 14);
        toggle(layout, preferences, "env_trace", R.string.env_trace, false);
        toggle(layout, preferences, "env_compat", R.string.env_compat, false);
        text(layout, R.string.env_switches_note, 14);
        text(layout, R.string.restart_note, 16);
        text(layout, R.string.probe_note, 14);
    }
    private void text(LinearLayout layout, int string, int size) {
        TextView view = new TextView(this);
        view.setText(string); view.setTextSize(size); view.setPadding(0, 12, 0, 20);
        layout.addView(view);
    }
    private void toggle(LinearLayout layout, SharedPreferences prefs, String key, int title, boolean fallback) {
        Switch view = new Switch(this);
        view.setText(title); view.setChecked(prefs.getBoolean(key, fallback));
        view.setPadding(0, 12, 0, 20);
        view.setOnCheckedChangeListener((button, checked) -> {
            SharedPreferences.Editor edit = prefs.edit().putBoolean(key, checked);
            if (key.equals("deny_bubble") && checked) edit.putLong("deny_bubble_epoch", System.currentTimeMillis());
            if (edit.commit()) Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show();
        });
        layout.addView(view);
    }
}
