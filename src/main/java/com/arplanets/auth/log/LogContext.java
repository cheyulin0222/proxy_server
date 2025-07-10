package com.arplanets.auth.log;

import com.arplanets.auth.model.RequestContext;
import com.arplanets.auth.utils.StringUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;


@Component
@RequiredArgsConstructor
@Slf4j
@Getter
public class LogContext {

    private static final String METADATA_BASE_URL = "http://169.254.169.254/latest";
    private static final String TOKEN_URL = METADATA_BASE_URL + "/api/token";
    private static final String INSTANCE_ID_URL = METADATA_BASE_URL + "/meta-data/instance-id";

    private final HttpServletRequest request;

    private String instanceId;

    @Value("${spring.profiles.active:unknown}")
    private String activeProfile;

    @Value("${git.commit.id.abbrev:UNKNOWN}")
    private String gitVersion;

    @Value("${application.service.id:UNKNOWN}")
    private String projectId;

    @PostConstruct
    public void initializeInstanceId() {

        this.instanceId = initInstanceId();
    }

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

    private String initInstanceId() {
            try {
                // 建立一個有短超時的 HTTP Client
                HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(2))
                        .build();

                // --- IMDSv2 流程：步驟 1 - 獲取 Token ---
                HttpRequest tokenRequest = HttpRequest.newBuilder()
                        .uri(URI.create(TOKEN_URL))
                        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600") // Token 有效期 6 小時
                        .PUT(HttpRequest.BodyPublishers.noBody())
                        .build();

                HttpResponse<String> tokenResponse = client.send(tokenRequest, HttpResponse.BodyHandlers.ofString());

                if (tokenResponse.statusCode() != 200) {
                    log.warn("無法獲取 IMDSv2 的 Token，HTTP 狀態碼: {}", tokenResponse.statusCode());
                    return "unknown";
                }
                String token = tokenResponse.body();

                // --- IMDSv2 流程：步驟 2 - 使用 Token 獲取 Instance ID ---
                HttpRequest idRequest = HttpRequest.newBuilder()
                        .uri(URI.create(INSTANCE_ID_URL))
                        .header("X-aws-ec2-metadata-token", token)
                        .GET()
                        .build();

                HttpResponse<String> idResponse = client.send(idRequest, HttpResponse.BodyHandlers.ofString());

                if (idResponse.statusCode() == 200) {
                    log.info("成功透過 HTTP 手動獲取並快取 EC2 Instance ID: {}", idResponse.body());
                    return idResponse.body();
                } else {
                    log.warn("無法獲取 Instance ID，HTTP 狀態碼: {}", idResponse.statusCode());
                    return "unknown";
                }

            } catch (IOException | InterruptedException e) {
                // 在本機或無法連線時會觸發此異常
                log.warn("無法連線到 EC2 中繼資料服務。如果不是在 EC2 上執行，這是正常現象。");
                return "unknown";
            }
        }
}
