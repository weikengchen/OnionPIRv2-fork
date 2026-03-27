package com.onionpir.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Safe wrapper around an async query queue handle.
 * <p>
 * The queue serializes PIR queries through a single worker thread,
 * providing non-blocking submit and pollable status/results.
 * <p>
 * The server used to create this queue must outlive the queue.
 */
public class OnionPirQueue implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;

    private Pointer handle;

    /**
     * Create a new query queue backed by the given server.
     * The server must outlive this queue.
     */
    public OnionPirQueue(OnionPirServer server) {
        handle = LIB.onion_queue_new(server.getHandle());
        if (handle == null) {
            throw new RuntimeException("Failed to create OnionPirQueue");
        }
    }

    /**
     * Submit a query for async processing.
     *
     * @param clientId client that generated the query
     * @param query    encrypted query bytes
     * @return ticket ID for tracking the query
     */
    public long submit(long clientId, byte[] query) {
        return LIB.onion_queue_submit(handle, clientId,
                query, new NativeLong(query.length));
    }

    /** Get the status of a submitted query. */
    public QueryStatus status(long ticket) {
        return QueryStatus.fromCode(LIB.onion_queue_status(handle, ticket));
    }

    /** Get the queue position of a submitted query. */
    public long position(long ticket) {
        return LIB.onion_queue_position(handle, ticket);
    }

    /**
     * Get the result of a completed query.
     *
     * @return decrypted response bytes, or null if the query is not done
     */
    public byte[] result(long ticket) {
        OnionBuf.ByValue buf = LIB.onion_queue_result(handle, ticket);
        if (buf.data == null) {
            return null;
        }
        return OnionPir.bufToBytes(buf);
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_queue_stop(handle);
            LIB.onion_queue_free(handle);
            handle = null;
        }
    }
}
