package io.github.lightjunction.alilogincompat;

final class UsbCompatPolicy {
    private UsbCompatPolicy() {}

    static boolean shouldReplace(String action, boolean compat) {
        return compat && "android.hardware.usb.action.USB_STATE".equals(action);
    }
}
