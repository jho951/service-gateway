package com.gateway.http;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;

import java.net.URI;
import java.net.InetSocketAddress;

import java.nio.charset.StandardCharsets;

import java.util.List;
import java.util.Map;

/**
 * {@link HttpExchange} 를 다루기 쉬운 메서드로 감싼 어댑터입니다.
 * <p>
 *  핸들러 내부가 JDK HTTP 서버의 저수준 API에 과도하게 결합되지 않도록
 *  요청 본문 읽기, JSON 응답 작성, 스트림 응답 전송을 이 클래스로 위임합니다.
 * </p>
 */
public final class ExchangeAdapter {
    private final HttpExchange exchange;

    /**
     * HTTP 응답의 "상태 코드(Status Code)"와 "본문의 길이(Content-Length)"를 클라이언트에게 미리 알려줍니다.
     * @param status HTTP 상태 코드
     * @param bodyLength 보낼 데이터(Body)의 바이트(Byte) 크기
     * @throws IOException 호출 후에 다른 헤더 정보를 추가 시 에러
     */
    private void sendHeaders(int status, long bodyLength) throws IOException {
        exchange.sendResponseHeaders(status, bodyLength);
    }
    /**
     * 생성자
     * @param exchange 현재 요청/응답 교환 객체
     */
    public ExchangeAdapter(HttpExchange exchange) {
        this.exchange = exchange;
    }
    /** @return HTTP 메서드*/
    public String method() {
        return exchange.getRequestMethod();
    }
    /** @return 요청 URI */
    public URI uri() {
        return exchange.getRequestURI();
    }
    /** @return 요청 헤더 */
    public Headers requestHeaders() {
        return exchange.getRequestHeaders();
    }
    /** @return 원격 클라이언트 주소 */
    public InetSocketAddress remoteAddress() {
        return exchange.getRemoteAddress();
    }

    /**
     * 요청 본문 전체를 메모리로 읽습니다.
     * @return 요청 바디 바이트 배열
     * @throws IOException 입출력 오류가 발생하면 전달됩니다
     */
    public byte[] readBody() throws IOException {
        try (InputStream input = exchange.getRequestBody(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            input.transferTo(output);
            return output.toByteArray();
        }
    }

    /**
     * JSON 오류 또는 상태 응답을 보냅니다.
     * @param status HTTP 상태 코드
     * @param json JSON 문자열
     * @throws IOException 응답 쓰기 실패 시 발생합니다
     */
    public void sendJson(int status, String json) throws IOException {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=UTF-8");
        sendHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }

    public void sendText(int status, String text) throws IOException {
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; version=0.0.4; charset=UTF-8");
        sendHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }

    /**
     * 응답 바디 없이 상태 코드만 전송합니다.
     * @param status HTTP 상태 코드
     * @throws IOException 응답 헤더 전송 실패 시 발생합니다
     */
    public void sendEmpty(int status) throws IOException {
        sendHeaders(status, -1);
        exchange.close();
    }

    /**
     * 업스트림 응답을 그대로 전달합니다.
     * @param status HTTP 상태 코드
     * @param headers 전달할 응답 헤더
     * @param payload 전달할 응답 바디
     * @throws IOException 응답 쓰기 실패 시 발생합니다
     */
    public void sendStream(int status, Map<String, List<String>> headers, byte[] payload) throws IOException {
        Headers responseHeaders = exchange.getResponseHeaders();
        headers.forEach((key, values) -> responseHeaders.put(key, values));
        sendHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }

    /** 현재 exchange 를 종료합니다. */
    public void close() {
        exchange.close();
    }
}
