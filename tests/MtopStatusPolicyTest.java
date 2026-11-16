package io.github.lightjunction.alilogincompat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class MtopStatusPolicyTest {
    private static void require(boolean condition) {
        if (!condition) throw new AssertionError();
    }
    private static void equal(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("unexpected sanitized result");
        }
    }

    private static void redaction() {
        equal("mtop.trade.query.bag", MtopStatusPolicy.normalizeApi("mtop.trade.query.bag"));
        for (String raw : new String[] {
                null, "", "mtop.", "mtop..bag", "mtop.trade.",
                "https://example.invalid/?token=private",
                "mtop.trade?sid=private", "mtop.trade/bag", "mtop.trade\nprivate",
                "mtop.trade\"private", "mtop.TOKEN", "mtop." + "a".repeat(160)
        }) equal(null, MtopStatusPolicy.normalizeApi(raw));
        equal("SUCCESS", MtopStatusPolicy.normalizeRet("SUCCESS::private response text"));
        equal("FAIL_SYS_USER_VALIDATE", MtopStatusPolicy.normalizeRet(
                "FAIL_SYS_USER_VALIDATE::cookie=private; signed request must not be logged"));
        equal("ANDROID_SYS_API_41X_ANTI_ATTACK", MtopStatusPolicy.normalizeRet(
                "ANDROID_SYS_API_41X_ANTI_ATTACK"));
        equal("ANDROID_SYS_NO_NETWORK", MtopStatusPolicy.normalizeRet("ANDROID_SYS_NO_NETWORK"));
        equal("UNAVAILABLE", MtopStatusPolicy.normalizeRet(null));
        equal("UNAVAILABLE", MtopStatusPolicy.normalizeRet(""));
        for (String raw : new String[] {
                "secret_cookie", "FAIL_SYS_", "ANDROID_SYS_", "FAIL_SYS_private",
                "FAIL_SYS_USER_VALIDATE\nsecret", "SUCCESS\"secret", "::secret",
                "{\"token\":\"private\"}", "FAIL_SYS_" + "A".repeat(88)
        }) equal("OTHER", MtopStatusPolicy.normalizeRet(raw));
        String longest = "FAIL_SYS_" + "A".repeat(87);
        equal(longest, MtopStatusPolicy.normalizeRet(longest + "::" + "private".repeat(1000)));

        MtopStatusPolicy policy = new MtopStatusPolicy();
        String line = policy.record(new Object(), MtopStatusPolicy.Stage.FILTER_ENTRY, 12,
                "https://example.invalid/?token=private", 419,
                "FAIL_SYS_USER_VALIDATE::private credentials");
        equal("{\"stage\":\"filter_entry\",\"elapsed_ms\":12,\"response_seq\":1,\"api\":null,"
                + "\"http\":419,\"ret\":\"FAIL_SYS_USER_VALIDATE\"}", line);
        require(!line.contains("private"));
    }

    private static void identityAndTransitions() {
        // The policy must not call methods on the application response.
        Object response = new Object() {
            @Override public String toString() { throw new AssertionError("response text accessed"); }
            @Override public int hashCode() { throw new AssertionError("response hash accessed"); }
            @Override public boolean equals(Object other) { throw new AssertionError("response equals accessed"); }
        };
        MtopStatusPolicy policy = new MtopStatusPolicy();
        String first = policy.record(response, MtopStatusPolicy.Stage.FILTER_ENTRY, 20,
                "mtop.trade.query.bag", 419, "FAIL_SYS_USER_VALIDATE");
        String finalRead = policy.record(response, MtopStatusPolicy.Stage.RET_READ, 30,
                "mtop.trade.query.bag", 419, "ANDROID_SYS_API_41X_ANTI_ATTACK");
        require(first.contains("\"response_seq\":1"));
        require(finalRead.contains("\"response_seq\":1"));
        require(finalRead.contains("\"stage\":\"ret_read\""));
        equal(null, policy.record(response, MtopStatusPolicy.Stage.RET_READ, 500,
                "mtop.trade.query.bag", 419, "ANDROID_SYS_API_41X_ANTI_ATTACK"));

        String changed = policy.record(response, MtopStatusPolicy.Stage.RET_READ, 600,
                "mtop.trade.query.bag", -1007, "ANDROID_SYS_NO_NETWORK");
        require(changed.contains("\"response_seq\":1"));
        require(changed.contains("\"http\":-1007"));
        String separate = policy.record(new Object(), MtopStatusPolicy.Stage.RET_READ, 601,
                "mtop.trade.query.bag", -1007, "ANDROID_SYS_NO_NETWORK");
        require(separate.contains("\"response_seq\":2"));
        equal(null, policy.record(null, MtopStatusPolicy.Stage.RET_READ, 700, null, 0, null));
    }

    private static void bounds() throws Exception {
        MtopStatusPolicy small = new MtopStatusPolicy(2);
        Object response = new Object();
        require(small.record(response, MtopStatusPolicy.Stage.FILTER_ENTRY, 1,
                "mtop.a", 419, "FAIL_SYS_USER_VALIDATE") != null);
        for (int i = 0; i < 1000; i++) equal(null, small.record(response,
                MtopStatusPolicy.Stage.FILTER_ENTRY, i, "mtop.a", 419, "FAIL_SYS_USER_VALIDATE"));
        require(!small.isFull());
        require(small.record(response, MtopStatusPolicy.Stage.RET_READ, 2,
                "mtop.a", 419, "ANDROID_SYS_API_41X_ANTI_ATTACK") != null);
        require(small.isFull());
        for (int i = 0; i < 10000; i++) equal(null, small.record(new Object(),
                MtopStatusPolicy.Stage.RET_READ, i, "mtop.a", 200, "SUCCESS"));

        MtopStatusPolicy concurrent = new MtopStatusPolicy();
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger emitted = new AtomicInteger();
        Thread[] workers = new Thread[8];
        for (int t = 0; t < workers.length; t++) {
            workers[t] = new Thread(() -> {
                try { start.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
                for (int i = 0; i < 1000; i++) {
                    if (concurrent.record(new Object(), MtopStatusPolicy.Stage.RET_READ, i,
                            "mtop.a", 200, "SUCCESS") != null) emitted.incrementAndGet();
                }
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread worker : workers) worker.join();
        equal(MtopStatusPolicy.MAX_RECORDS, emitted.get());
        require(concurrent.isFull());
    }

    public static void main(String[] args) throws Exception {
        redaction();
        identityAndTransitions();
        bounds();
        System.out.println("MTOP status redaction, identity, deduplication, and bounds tests passed");
    }
}
