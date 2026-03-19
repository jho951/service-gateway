package com.gateway;

import com.gateway.config.GatewayConfig;
import com.gateway.config.RuntimeEnvironment;
import com.gateway.server.GatewayServer;

/**
 * API Gateway 애플리케이션의 진입점입니다.
 *
 * <p>프로세스 시작 시 환경 변수를 읽어 {@link GatewayConfig} 를 구성하고,
 * 해당 설정으로 {@link GatewayServer} 를 부팅합니다. 애플리케이션은 별도의
 * 비즈니스 로직을 직접 수행하지 않고, 외부 요청을 받아 인증/보안/라우팅 정책을
 * 적용하는 단일 진입 서버 역할만 담당합니다.</p>
 */
public final class GatewayApplication {
    private GatewayApplication() {}

    /**
     * 시스템 환경 변수 기반 설정으로 게이트웨이 서버를 시작합니다.
     *
     * @param args 사용하지 않는 명령행 인자
     * @throws Exception 설정 파싱 실패 또는 서버 시작 실패 시 발생합니다
     */
    public static void main(String[] args) throws Exception {
        RuntimeEnvironment.ResolvedEnvironment runtimeEnvironment = RuntimeEnvironment.load(args);
        GatewayConfig config = GatewayConfig.fromEnv(runtimeEnvironment.variables());
        System.out.printf(
                "Starting gateway with profile '%s' using %s%n",
                runtimeEnvironment.profile(),
                runtimeEnvironment.envFile()
        );
        GatewayServer server = new GatewayServer(config);
        server.start();
    }
}
