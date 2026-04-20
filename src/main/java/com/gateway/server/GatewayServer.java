package com.gateway.server;

import com.gateway.config.GatewayConfig;
import com.gateway.metrics.GatewayMetrics;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

import java.util.logging.Logger;
import java.util.concurrent.Executors;

/**
 * JDK 내장 HTTP 서버를 이용해 게이트웨이 런타임을 구동합니다.
 * <p>
 * 모든 요청은 루트 컨텍스트 하나로 수신되고,
 * 실제 정책 집행은 {@link GatewayHandler} 가 담당합니다.
 * </p>
 */
public final class GatewayServer {
    private static final Logger log = Logger.getLogger(GatewayServer.class.getName());

    private final GatewayConfig config;
    private final GatewayMetrics metrics = new GatewayMetrics();

    /** @param config 게이트웨이 런타임 설정 */
    public GatewayServer(GatewayConfig config) {
        this.config = config;
    }

    /**
     * 서버를 생성하고 지정된 주소로 바인드한 뒤 요청 수신을 시작합니다.
     *
     * @throws IOException 포트 바인딩 또는 서버 초기화 실패 시 발생합니다
     */
    public void start() throws IOException {
        InetSocketAddress bindAddress = config.bindAddress();
        HttpServer server = HttpServer.create(bindAddress, 0);
        server.createContext("/", new GatewayHandler(config, metrics));
        server.setExecutor(Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
        server.start();
        log.info(() -> "API gateway listening on " + bindAddress.getHostString() + ":" + bindAddress.getPort());
    }
}
