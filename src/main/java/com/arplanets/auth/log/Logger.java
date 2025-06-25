package com.arplanets.auth.log;

import java.util.Map;

public class Logger {

    private static LoggingService loggingService;

    static void initializeLoggingService(LoggingService service) {
        loggingService = service;
    }

    public static void info(String message) {
        loggingService.info(message);
    }

    public static void info(String message, Map<String, Object> context) {
        loggingService.info(message, context);
    }

    public static void warn(String message) {
        loggingService.warn(message);
    }

    public static void error(String message) {
        loggingService.error(message);
    }

    public static void error(String message, ErrorType errorType) {
        loggingService.error(message, errorType);
    }

    public static void error(String message, ErrorType errorType, Map<String, Object> context) {
        loggingService.error(message, errorType, context);
    }

    public static void error(String message, ErrorType errorType, Throwable error) {
        loggingService.error(message, errorType, error);
    }

    public static void error(String message, ErrorType errorType, Throwable error, Map<String, Object> context) {
        loggingService.error(message, errorType, error, context);
    }
}
