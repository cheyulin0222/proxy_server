package com.arplanets.auth.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashSet;
import java.util.Set;

public class JsonUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static <T> String convertSetToJsonString(Set<T> set) {
        try {
            return objectMapper.writeValueAsString(set);
        } catch (Exception e) {
            throw new RuntimeException("无法将集合转换为 JSON", e);
        }
    }

    public static <T> Set<T> convertJsonStringToSet(String json, Class<T> elementType) {
        try {
            if (json == null || json.isEmpty()) {
                return new HashSet<>();
            }
            JavaType type = objectMapper.getTypeFactory().constructCollectionType(Set.class, elementType);
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            throw new RuntimeException("无法将 JSON 转换为集合", e);
        }
    }
}
