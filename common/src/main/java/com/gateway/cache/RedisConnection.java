package com.gateway.cache;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Redis RESP을 최소한으로 구현하여 직접 요청을 보내는 헬퍼 클래스입니다.
 */
public final class RedisConnection implements AutoCloseable {
    private final Socket socket;
    private final BufferedInputStream in;
    private final BufferedOutputStream out;

    public RedisConnection(String host, int port, int timeoutMs) throws IOException {
        this(host, port, timeoutMs, null);
    }

    public RedisConnection(String host, int port, int timeoutMs, String password) throws IOException {
        this.socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), timeoutMs);
        socket.setSoTimeout(timeoutMs);
        this.in = new BufferedInputStream(socket.getInputStream());
        this.out = new BufferedOutputStream(socket.getOutputStream());
        authenticate(password);
    }

    public String get(String key) throws IOException {
        writeArray("GET", key);
        out.flush();
        return readBulkString();
    }

    public void setEx(String key, int ttlSeconds, String value) throws IOException {
        writeArray("SETEX", key, String.valueOf(ttlSeconds), value);
        out.flush();
        readSimpleString();
    }

    private void authenticate(String password) throws IOException {
        if (password == null || password.isBlank()) {
            return;
        }
        writeArray("AUTH", password);
        out.flush();
        readSimpleString();
    }

    private void writeArray(String... values) throws IOException {
        out.write(("*" + values.length + "\r\n").getBytes(StandardCharsets.UTF_8));
        for (String value : values) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            out.write(("$" + bytes.length + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(bytes);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }
    }

    private String readBulkString() throws IOException {
        int type = in.read();
        if (type == '$') {
            int length = Integer.parseInt(readLine());
            if (length < 0) {
                return null;
            }
            byte[] payload = in.readNBytes(length);
            readCrlf();
            return new String(payload, StandardCharsets.UTF_8);
        }
        if (type == '-') {
            throw new IOException(readLine());
        }
        throw new IOException("Unexpected Redis response type: " + (char) type);
    }

    private void readSimpleString() throws IOException {
        int type = in.read();
        if (type == '+') {
            readLine();
            return;
        }
        if (type == '-') {
            throw new IOException(readLine());
        }
        throw new IOException("Unexpected Redis response type: " + (char) type);
    }

    private String readLine() throws IOException {
        StringBuilder builder = new StringBuilder();
        int current;
        while ((current = in.read()) != -1) {
            if (current == '\r') {
                int next = in.read();
                if (next == '\n') {
                    break;
                }
            } else {
                builder.append((char) current);
            }
        }
        return builder.toString();
    }

    private void readCrlf() throws IOException {
        if (in.read() != '\r' || in.read() != '\n') {
            throw new IOException("Invalid Redis CRLF");
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
