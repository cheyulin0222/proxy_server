package com.arplanets.auth.log;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
@Getter
public class LogContext {

    private final HttpServletRequest request;

    @Value("${cloud.aws.instance.id:unknown}")
    private String instanceId;

    @Value("${spring.profiles.active:unknown}")
    private String activeProfile;

    @Value("${git.commit.id.abbrev:UNKNOWN}")
    private String gitVersion;

    @Value("${application.service.id:UNKNOWN}")
    private String projectId;

    public String getSessionId() {
        if (request != null && request.getSession(false) != null) {
            return request.getSession(false).getId();
        }
        return null;
    }

    public String getRequestId() {
        return (String) request.getAttribute("requestId");
    }

    public String getLogSn() {
        return generateId("log");
    }

    public String getMethod() {
        return request.getMethod();
    }

    public String getURI() {
        return request.getRequestURI();
    }

    public String getClassName() {
        return StackWalker.getInstance()
                .walk(frames -> frames
                        .skip(4)
                        .findFirst()
                        .map(StackWalker.StackFrame::getClassName)
                        .orElse("Unknown"));
    }

    public String getMethodName() {
        return StackWalker.getInstance()
                .walk(frames -> frames
                        .skip(4)
                        .findFirst()
                        .map(StackWalker.StackFrame::getMethodName)
                        .orElse("Unknown"));
    }

    public String generateId(String prefix) {
        ZoneId taipeiZone = ZoneId.of("Asia/Taipei");
        String timestamp = LocalDateTime.now(taipeiZone)
                .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));

        return "%s-%s-%s-%s".formatted(prefix, getProjectId(), timestamp, UUID.randomUUID().toString());
    }
}
