package com.arplanets.auth.log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.logging.LogLevel;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class LoggingService {

    private final LogContext logContext;
    private final ObjectMapper objectMapper;

    public void info(String message) {
        executeLogging(() -> log(LogLevel.INFO, message, null, null), message);
    }



    public void info(String message, Map<String, Object> context) {
        executeLogging(() -> log(LogLevel.INFO, message, context, null), message);

    }

    public void warn(String message) {
        executeLogging(() -> log(LogLevel.WARN, message, null, null), message);
    }

    public void error(String message) {
        executeLogging(() -> log(LogLevel.ERROR, message, null, null), message);
    }

    public void error(String message, ErrorType errorType) {
        ErrorData errorData = ErrorData.builder()
                .message(message)
                .errorType(errorType)
                .build();

        executeLogging(() -> log(LogLevel.ERROR, message, null, errorData), message);
    }



    public void error(String message, ErrorType errorType, Map<String, Object> context) {
        ErrorData errorData = ErrorData.builder()
                .message(message)
                .errorType(errorType)
                .build();

        executeLogging(() -> log(LogLevel.ERROR, message, context, errorData), message);
    }

    public void error(String message, ErrorType errorType, Throwable error) {
        ErrorData errorData = ErrorData.builder()
                .message(message + " | " + error.getMessage())
                .errorType(errorType)
                .stackTrace(Arrays.toString(error.getStackTrace()))
                .build();

        executeLogging(() -> log(LogLevel.ERROR, message, null, errorData), message);
    }

    public void error(String message, ErrorType errorType, Throwable error, Map<String, Object> context) {
        ErrorData errorData = ErrorData.builder()
                .message(message + " | " + error.getMessage())
                .errorType(errorType)
                .stackTrace(Arrays.toString(error.getStackTrace()))
                .build();

        executeLogging(() -> log(LogLevel.ERROR, message, context, errorData), message);
    }

    private void log(LogLevel level, String message, Map<String, Object> context, ErrorData errorData) {
        try {
            LogMessage logMessage = LogMessage.builder()
                    .logSn(logContext.getLogSn())
                    .projectId(logContext.getProjectId())
                    .stage(logContext.getActiveProfile())
                    .instanceId(logContext.getInstanceId())
                    .sessionId(logContext.getSessionId())
                    .requestId(logContext.getRequestId())
                    .method(logContext.getMethod())
                    .uri(logContext.getURI())
                    .logLevel(level.name().toLowerCase())
                    .className(logContext.getClassName())
                    .methodName(logContext.getMethodName())
                    .context(context)
                    .message(message)
                    .errorData(errorData)
                    .version(logContext.getGitVersion())
                    .timestamp(new Timestamp(
                            LocalDateTime.now(ZoneId.of("Asia/Taipei"))
                                    .toInstant(ZoneOffset.ofHours(8))
                                    .toEpochMilli()
                    ))
                    .build();

            String jsonLog = objectMapper.writeValueAsString(logMessage);

            switch (level) {
                case INFO -> log.info("{}", jsonLog);
                case ERROR -> log.error("{}", jsonLog);
                default -> log.debug("{}", jsonLog);
            }
        } catch (JsonProcessingException e) {
            log.error("Error creating JSON log");
        }
    }

    private void executeLogging(Runnable loggingAction, String originalMessage) {
        try {
            loggingAction.run();
        } catch (Exception e) {
            log.warn("Failed to process and log message: '{}'", originalMessage, e);
        }
    }
}
