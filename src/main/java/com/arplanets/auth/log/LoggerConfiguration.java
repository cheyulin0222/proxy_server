package com.arplanets.auth.log;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class LoggerConfiguration {

    private final LogContext logContext;
    private final ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        Logger.initializeLoggingService(new LoggingService(logContext, objectMapper));
    }
}
