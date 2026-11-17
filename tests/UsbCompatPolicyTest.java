package io.github.lightjunction.alilogincompat;

public final class UsbCompatPolicyTest {
    public static void main(String[] args) {
        assert UsbCompatPolicy.shouldReplace("android.hardware.usb.action.USB_STATE", true);
        assert !UsbCompatPolicy.shouldReplace("android.hardware.usb.action.USB_STATE", false);
        assert !UsbCompatPolicy.shouldReplace("android.intent.action.BATTERY_CHANGED", true);
        assert !UsbCompatPolicy.shouldReplace(null, true);
    }
}
