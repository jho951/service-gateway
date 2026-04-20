package com.gateway.exception;

import java.util.Objects;

/** 예외를 HTTP 응답으로 변환한 결과를 담는 값 객체입니다. */
public final class ResponseSpec {
    private final int httpStatus;
    private final String jsonBody;

    public ResponseSpec(int httpStatus, String jsonBody) {
        this.httpStatus = httpStatus;
        this.jsonBody = jsonBody;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getJsonBody() {
        return jsonBody;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResponseSpec)) return false;
        ResponseSpec that = (ResponseSpec) o;
        return httpStatus == that.httpStatus &&
                Objects.equals(jsonBody, that.jsonBody);
    }

    @Override
    public int hashCode() {
        return Objects.hash(httpStatus, jsonBody);
    }

    @Override
    public String toString() {
        return "ResponseSpec{" +
                "httpStatus=" + httpStatus +
                ", jsonBody='" + jsonBody + '\'' +
                '}';
    }
}
