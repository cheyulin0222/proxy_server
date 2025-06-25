package com.arplanets.auth.log;

import com.arplanets.auth.model.RequestContext;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


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
        if (request != null && request.getAttribute("requestContext") != null) {
            RequestContext requestContext = (RequestContext) request.getAttribute("requestContext");
            return requestContext.getRequestId();
        }
        return null;
    }

    public String getLogSn() {
        return StringUtil.generateId("log");
    }

    public String getMethod() {
        return (request != null) ? request.getMethod() : null;
    }

    public String getURI() {
        return (request != null) ? request.getRequestURI() : null;
    }

    public String getClassName() {
        return StackWalker.getInstance()
                .walk(frames -> frames
                        .skip(6)
                        .findFirst()
                        .map(StackWalker.StackFrame::getClassName)
                        .orElse("Unknown"));
    }

    public String getMethodName() {
        return StackWalker.getInstance()
                .walk(frames -> frames
                        .skip(6)
                        .findFirst()
                        .map(StackWalker.StackFrame::getMethodName)
                        .orElse("Unknown"));
    }

}
