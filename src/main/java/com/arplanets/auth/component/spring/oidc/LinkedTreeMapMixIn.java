package com.arplanets.auth.component.spring.oidc;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

// 這個 Mixin 旨在讓 Jackson 允許反序列化 LinkedTreeMap
// 通常，它只需要非常少的內容，或者甚至只是一個空的接口，
// 只要它被 ObjectMapper 註冊為 com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap 的 Mixin
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) // 告訴Jackson在序列化時包含類型信息，反序列化時使用
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY, // 允許訪問所有字段
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        setterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.ANY // 允许使用构造函数进行反序列化
)
@JsonIgnoreProperties(ignoreUnknown = true) // 忽略不認識的屬性
public abstract class LinkedTreeMapMixIn {
}
