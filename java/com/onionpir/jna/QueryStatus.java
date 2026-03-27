package com.onionpir.jna;

/**
 * Status codes for async query queue tickets.
 * Maps to ONION_QUERY_* constants in ffi_c.h.
 */
public enum QueryStatus {
    QUEUED(0),
    PROCESSING(1),
    DONE(2),
    ERROR(3),
    NOT_FOUND(4);

    private final int code;

    QueryStatus(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static QueryStatus fromCode(int code) {
        for (QueryStatus s : values()) {
            if (s.code == code) return s;
        }
        return NOT_FOUND;
    }
}
