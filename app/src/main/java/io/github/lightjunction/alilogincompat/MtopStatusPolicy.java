package io.github.lightjunction.alilogincompat;

import java.lang.ref.WeakReference;
import java.util.Objects;

/** Bounded, credential-free formatting shared by the observer and JVM tests. */
final class MtopStatusPolicy {
    static final int MAX_RECORDS = 128;
    enum Stage {
        FILTER_ENTRY("filter_entry"), RET_READ("ret_read");
        final String label;
        Stage(String label) { this.label = label; }
    }

    private final WeakReference<?>[] responses;
    private final int[] responseIds;
    private final Record[] records;
    private int nextResponseId, count;

    MtopStatusPolicy() { this(MAX_RECORDS); }
    MtopStatusPolicy(int limit) {
        if (limit < 1 || limit > MAX_RECORDS) throw new IllegalArgumentException("invalid record limit");
        responses = new WeakReference<?>[limit];
        responseIds = new int[limit];
        records = new Record[limit];
    }

    synchronized boolean isFull() { return count == records.length; }

    synchronized String record(Object response, Stage stage, long elapsedMs,
                               String api, int http, String ret) {
        if (response == null || stage == null || count == records.length) return null;
        int responseId = responseId(response);
        if (responseId == 0) return null;
        Record item = new Record(stage, Math.max(0L, elapsedMs), responseId,
                                 normalizeApi(api), http, normalizeRet(ret));
        for (int i = 0; i < count; i++) if (records[i].sameStatus(item)) return null;
        records[count++] = item;
        return item.json();
    }

    private int responseId(Object response) {
        int empty = -1;
        for (int i = 0; i < responses.length; i++) {
            Object existing = responses[i] == null ? null : responses[i].get();
            if (existing == response) return responseIds[i];
            if (empty == -1 && existing == null) empty = i;
        }
        if (empty == -1) return 0;
        responses[empty] = new WeakReference<>(response);
        responseIds[empty] = ++nextResponseId;
        return nextResponseId;
    }

    static String normalizeApi(String api) {
        if (api == null || api.length() > 160 || !api.startsWith("mtop.")) return null;
        boolean segment = false;
        for (int i = 5; i < api.length(); i++) {
            char c = api.charAt(i);
            if (c == '.') {
                if (!segment) return null;
                segment = false;
            } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                segment = true;
            } else return null;
        }
        return segment ? api : null;
    }

    static String normalizeRet(String raw) {
        if (raw == null || raw.isEmpty()) return "UNAVAILABLE";
        int end = raw.length();
        for (int i = 0; i <= 96 && i + 1 < raw.length(); i++) {
            if (raw.charAt(i) == ':' && raw.charAt(i + 1) == ':') {
                end = i;
                break;
            }
        }
        if (end == 0 || end > 96) return "OTHER";
        String code = raw.substring(0, end);
        if (!code.equals("SUCCESS") && !(code.startsWith("FAIL_SYS_") && code.length() > 9)
                && !(code.startsWith("ANDROID_SYS_") && code.length() > 12)) return "OTHER";
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) return "OTHER";
        }
        return code;
    }

    private static final class Record {
        final Stage stage;
        final long elapsedMs;
        final int responseId, http;
        final String api, ret;
        Record(Stage stage, long elapsedMs, int responseId, String api, int http, String ret) {
            this.stage = stage; this.elapsedMs = elapsedMs; this.responseId = responseId;
            this.api = api; this.http = http; this.ret = ret;
        }
        boolean sameStatus(Record other) {
            return stage == other.stage && responseId == other.responseId && http == other.http
                    && Objects.equals(api, other.api) && ret.equals(other.ret);
        }
        String json() {
            // Both strings have already passed ASCII-only validation; no raw text is serialized.
            return "{\"stage\":\"" + stage.label + "\",\"elapsed_ms\":" + elapsedMs
                    + ",\"response_seq\":" + responseId + ",\"api\":"
                    + (api == null ? "null" : "\"" + api + "\"")
                    + ",\"http\":" + http + ",\"ret\":\"" + ret + "\"}";
        }
    }
}
