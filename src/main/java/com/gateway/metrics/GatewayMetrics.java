package com.gateway.metrics;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

public final class GatewayMetrics {
    private final long startedAtMillis = System.currentTimeMillis();
    private final ConcurrentHashMap<RequestKey, RequestStats> requests = new ConcurrentHashMap<>();
    private final AtomicLong inFlightRequests = new AtomicLong();

    public void incrementInFlight() {
        inFlightRequests.incrementAndGet();
    }

    public void decrementInFlight() {
        inFlightRequests.decrementAndGet();
    }

    public void recordRequest(String method, String upstream, int status, String authOutcome, long elapsedMillis) {
        RequestKey key = new RequestKey(
                labelValue(method),
                labelValue(upstream),
                String.valueOf(status),
                labelValue(authOutcome)
        );
        requests.computeIfAbsent(key, ignored -> new RequestStats()).record(elapsedMillis);
    }

    public String scrape() {
        StringBuilder builder = new StringBuilder();
        builder.append("# HELP gateway_up Gateway process liveness.\n")
                .append("# TYPE gateway_up gauge\n")
                .append("gateway_up 1\n")
                .append("# HELP gateway_started_at_millis Gateway process start timestamp in milliseconds.\n")
                .append("# TYPE gateway_started_at_millis gauge\n")
                .append("gateway_started_at_millis ").append(startedAtMillis).append('\n')
                .append("# HELP gateway_http_requests_active Current in-flight gateway HTTP requests.\n")
                .append("# TYPE gateway_http_requests_active gauge\n")
                .append("gateway_http_requests_active ").append(inFlightRequests.get()).append('\n')
                .append("# HELP gateway_http_requests_total Total gateway HTTP requests.\n")
                .append("# TYPE gateway_http_requests_total counter\n");

        for (Map.Entry<RequestKey, RequestStats> entry : requests.entrySet()) {
            RequestKey key = entry.getKey();
            RequestStats stats = entry.getValue();
            builder.append("gateway_http_requests_total")
                    .append(labels(key))
                    .append(' ')
                    .append(stats.count.sum())
                    .append('\n');
        }

        builder.append("# HELP gateway_http_request_duration_seconds_sum Total gateway HTTP request duration in seconds.\n")
                .append("# TYPE gateway_http_request_duration_seconds_sum counter\n");
        for (Map.Entry<RequestKey, RequestStats> entry : requests.entrySet()) {
            builder.append("gateway_http_request_duration_seconds_sum")
                    .append(labels(entry.getKey()))
                    .append(' ')
                    .append(entry.getValue().durationMillis.sum() / 1000.0)
                    .append('\n');
        }

        builder.append("# HELP gateway_http_request_duration_seconds_count Gateway HTTP request duration sample count.\n")
                .append("# TYPE gateway_http_request_duration_seconds_count counter\n");
        for (Map.Entry<RequestKey, RequestStats> entry : requests.entrySet()) {
            builder.append("gateway_http_request_duration_seconds_count")
                    .append(labels(entry.getKey()))
                    .append(' ')
                    .append(entry.getValue().count.sum())
                    .append('\n');
        }

        return builder.toString();
    }

    private static String labels(RequestKey key) {
        return "{method=\"" + escape(key.method)
                + "\",upstream=\"" + escape(key.upstream)
                + "\",status=\"" + escape(key.status)
                + "\",auth_outcome=\"" + escape(key.authOutcome)
                + "\"}";
    }

    private static String labelValue(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private record RequestKey(String method, String upstream, String status, String authOutcome) {
    }

    private static final class RequestStats {
        private final LongAdder count = new LongAdder();
        private final LongAdder durationMillis = new LongAdder();

        private void record(long elapsedMillis) {
            count.increment();
            durationMillis.add(Math.max(elapsedMillis, 0));
        }
    }
}

