package com.arplanets.auth.log;

import com.arplanets.auth.serializer.TimestampToTaipeiISOSerializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Builder;
import lombok.Data;

import java.sql.Timestamp;
import java.util.Map;

@Data
@Builder
@JsonPropertyOrder({
        "log_sn",
        "project_id",
        "stage",
        "instance_id",
        "session_id",
        "request_id",
        "method",
        "uri",
        "log_level",
        "class_name",
        "method_name",
        "message",
        "context",
        "error_data",
        "version",
        "timestamp"
})
public class LogMessage {

    @JsonProperty("log_sn")
    private String logSn;

    @JsonProperty("project_id")
    private String projectId;

    private String stage;

    @JsonProperty("instance_id")
    private String instanceId;

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("request_id")
    private String requestId;

    private String method;

    private String uri;

    @JsonProperty("log_level")
    private String logLevel;

    @JsonProperty("class_name")
    private String className;

    @JsonProperty("method_name")
    private String methodName;

    private String message;

    private Map<String, Object> context;

    @JsonProperty("error_data")
    private ErrorData errorData;

    private String version;

    @JsonSerialize(using = TimestampToTaipeiISOSerializer.class)
    private Timestamp timestamp;
}
