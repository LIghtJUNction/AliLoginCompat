package io.github.lightjunction.alilogincompat;

public final class DenyLocationPolicyTest {
    public static void main(String[] args) {
        String page = "https://bixi.alicdn.com/punish/punish:resource:template:baba:default_35969158.html";
        require(DenyLocationPolicy.shouldReplace(page + "?uuid=sample&action=deny"));
        require(DenyLocationPolicy.shouldReplace(page + "?action=%64eny"));
        for (String value : new String[]{null, "", page, page + "?action=captcha",
                page + "?action=deny&action=captcha", page + "#action=deny",
                "https://bixi.alicdn.com.evil.invalid/punish/test?action=deny",
                "https://user@bixi.alicdn.com/punish/test?action=deny",
                "http://bixi.alicdn.com/punish/test?action=deny",
                "https://bixi.alicdn.com:444/punish/test?action=deny",
                "https://bixi.alicdn.com/other?action=deny"}) {
            require(!DenyLocationPolicy.shouldReplace(value));
        }
    }
    private static void require(boolean value) {
        if (!value) throw new AssertionError();
    }
}
