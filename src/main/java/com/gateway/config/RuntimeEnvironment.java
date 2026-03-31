package com.gateway.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 실행 프로필과 env 파일을 해석해 애플리케이션 설정 입력을 구성합니다. */
public final class RuntimeEnvironment {
    private RuntimeEnvironment() {}

    public static ResolvedEnvironment load(String[] args) {
        Map<String, String> systemEnv = System.getenv();
        ParsedArgs parsedArgs = ParsedArgs.from(args);

        String profile = firstNonBlank(parsedArgs.profile(), systemEnv.get("APP_ENV"), "local");
        Path envFile = resolveEnvFile(parsedArgs.envFile(), systemEnv.get("APP_ENV_FILE"), profile);

        Map<String, String> merged = new LinkedHashMap<>(loadEnvFile(envFile));
        merged.putAll(systemEnv);
        merged.put("APP_ENV", profile);
        merged.put("APP_ENV_FILE", envFile.toString());

        return new ResolvedEnvironment(profile, envFile, Map.copyOf(merged));
    }

    private static Path resolveEnvFile(String argEnvFile, String systemEnvFile, String profile) {
        String rawPath = firstNonBlank(argEnvFile, systemEnvFile, defaultEnvFile(profile));
        return Paths.get(rawPath).toAbsolutePath().normalize();
    }

    private static String defaultEnvFile(String profile) {
        return switch (profile) {
            case "local", "dev" -> ".env.dev";
            case "prod" -> ".env.prod";
            default -> ".env." + profile;
        };
    }

    private static Map<String, String> loadEnvFile(Path envFile) {
        if (!Files.exists(envFile)) {
            throw new IllegalArgumentException("Environment file not found: " + envFile);
        }

        Map<String, String> values = new LinkedHashMap<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(envFile);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Failed to read environment file: " + envFile, ex);
        }

        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            int separator = line.indexOf('=');
            if (separator <= 0) {
                throw new IllegalArgumentException("Invalid env entry: " + rawLine);
            }

            String key = line.substring(0, separator).trim();
            String value = normalizeValue(line.substring(separator + 1).trim());
            values.put(key, value);
        }
        return values;
    }

    private static String normalizeValue(String rawValue) {
        if (rawValue.length() >= 2) {
            boolean doubleQuoted = rawValue.startsWith("\"") && rawValue.endsWith("\"");
            boolean singleQuoted = rawValue.startsWith("'") && rawValue.endsWith("'");
            if (doubleQuoted || singleQuoted) {
                return rawValue.substring(1, rawValue.length() - 1);
            }
        }
        return rawValue;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate.trim();
            }
        }
        return null;
    }

    public record ResolvedEnvironment(String profile, Path envFile, Map<String, String> variables) {}

    private record ParsedArgs(String profile, String envFile) {
        private static ParsedArgs from(String[] args) {
            String profile = null;
            String envFile = null;

            for (int index = 0; index < args.length; index++) {
                String arg = args[index];
                if (arg.startsWith("--profile=")) {
                    profile = arg.substring("--profile=".length());
                    continue;
                }
                if (arg.equals("--profile") && index + 1 < args.length) {
                    profile = args[++index];
                    continue;
                }
                if (arg.startsWith("--env-file=")) {
                    envFile = arg.substring("--env-file=".length());
                    continue;
                }
                if (arg.equals("--env-file") && index + 1 < args.length) {
                    envFile = args[++index];
                }
            }

            return new ParsedArgs(profile, envFile);
        }
    }
}
