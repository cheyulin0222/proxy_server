package com.arplanets.auth.utils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class StringUtil {

    public static String STATE = "state";
    public static String CODE = "code";
    public static String ACCESS_TOKEN_PARAM_NAME = "access_token";
    public static String REFRESH_TOKEN_PARAM_NAME = "refresh_token";
    public static String ID_TOKEN_PARAM_NAME = "id_token";
    public static String ROOT_PATH = "/";
    public static String FAVICON_PATH = "/favicon.ico";
    public static String LOGIN_PATH = "/login";
//    public static String LOGOUT_CALLBACK_PATH = "/logout/callback";
    public static String ERROR_PATH = "/error";
    public static String CLIENT_ID_ATTRIBUTE_NAME = "client_id";
    public static String REGISTRATION_ID_ATTRIBUTE_NAME = "registration_id";
    public static String AUTH_SESSION_ID = "authenticated_session_id";
    public static String AUTH_ID = "auth_id";
    public static String SID_CLAIM_NAME = "sid";
    public static String SUB_CLAIM_NAME = "sub";
    public static String UUID_CLAIM_NAME = "uuid";
    public static String TOKEN_TYPE_HINT_PARAM_NAME = "token_type_hint";
    public static String END_SESSION_ENDPOINT_ATTR_NAME = "end_session_endpoint";
    public static String ID_TOKEN_HINT_PARAM_NAME = "id_token_hint";
    public static String REDIRECT_URI_PARAM_NAME = "redirect_uri";
    public static String LOGOUT_URI_PARAM_NAME = "logout_uri";
    public static String POST_LOGOUT_REDIRECT_URI_PARAM_NAME = "post_logout_redirect_uri";


    public static String COGNITO_PROVIDER_NAME = "cognito";


    public static String generateId(String prefix) {
        ZoneId taipeiZone = ZoneId.of("Asia/Taipei");
        String timestamp = LocalDateTime.now(taipeiZone)
                .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));

        return "%s-%s-%s".formatted(prefix, timestamp, UUID.randomUUID().toString());
    }

}
