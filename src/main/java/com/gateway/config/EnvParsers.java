package com.gateway.config;

import java.util.List;

/**
 * 환경 변수 문자열을 게이트웨이 설정 객체로 변환할 때 사용하는 공통 파서입니다.
 * <p>
 * 현재는 단순 CSV 형태의 목록 파싱만 담당하지만, 설정 규칙이 늘어날 경우
 * 문자열 기반 설정 해석 로직을 이 클래스로 집중시키는 것을 의도합니다.
 * </p>
 */
public final class EnvParsers {
    private EnvParsers() {}

    /**
     * 쉼표로 구분된 문자열을 공백 제거 후 목록으로 변환합니다.
     * @param raw 원본 환경 변수 값
     * @return 비어 있지 않은 항목만 포함하는 불변 리스트
     */
    public static List<String> csv(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        return List.of(raw.split(",")).stream()
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toList();
    }

    /**
     * CSV 파싱 결과가 비어 있으면 기본 목록을 반환합니다.
     * @param raw 원본 환경 변수 값
     * @param defaultValue 값이 없을 때 사용할 기본 목록
     * @return 파싱된 목록 또는 기본 목록
     */
    public static List<String> csvOrDefault(String raw, List<String> defaultValue) {
        List<String> parsed = csv(raw);
        return parsed.isEmpty() ? defaultValue : parsed;
    }
}
