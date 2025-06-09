package com.arplanets.auth.repository.inmemory;

import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

@Component
@Slf4j
public class TenantRepository {

    // 不同 Tenant 的 Tenant ID 對應 不同的 Map 物件
    // Map 物件以 Class 類別作 Key ， Value 為具體的實作
    private final ConcurrentMap<String, Map<Class<?>, Object>> registry = new ConcurrentHashMap<>();

    public <T> void register(String tenantId, Class<T> componentClass, T component) {
        Assert.hasText(tenantId, "tenantId cannot be empty");
        Assert.notNull(componentClass, "componentClass cannot be null");
        Assert.notNull(component, "component cannot be null");
        Map<Class<?>, Object> components = this.registry.computeIfAbsent(tenantId, key -> new ConcurrentHashMap<>());
        components.put(componentClass, component);
        log.info("Registered component {} for tenantId '{}'", componentClass.getSimpleName(), tenantId);
    }

    @Nullable
    public <T> T get(Class<T> componentClass) {
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        if (context == null || context.getIssuer() == null) {
            log.warn("Cannot get component, AuthorizationServerContext or Issuer is null.");
            return null;
        }

        String runtimeIssuer = context.getIssuer();
        String tenantId = extractPathAfterDomain(runtimeIssuer);

        if (tenantId.isBlank()) {
            log.warn("Could not extract tenant identifier from runtime issuer: {}", runtimeIssuer);
            return null;
        }

        Map<Class<?>, Object> components = this.registry.get(tenantId);
        if (components != null) {
            Object component = components.get(componentClass);
            if (component != null) {
                log.debug("Found component {} for tenant '{}'", componentClass.getSimpleName(), tenantId);
                return componentClass.cast(component);
            } else {
                log.warn("Component type {} not found for tenant '{}' in registry.", componentClass.getSimpleName(), tenantId);
            }
        } else {
            log.warn("No components registered for tenant identifier '{}' (derived from issuer '{}')", tenantId, runtimeIssuer);
        }

        return null;

    }

    public <T> List<T> getAll(Class<T> componentClass) {
        Assert.notNull(componentClass, "componentClass cannot be null");
        return registry.values().stream()
                .map(tenantComponents -> tenantComponents.get(componentClass))
                .map(componentClass::cast)
                .collect(Collectors.toList());
    }

    public void remove(String tenantId) {
        this.registry.remove(tenantId);
    }

    private String extractPathAfterDomain(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return "";
        }

        try {
            URI uri = new URI(issuer);
            String path = uri.getPath();

            if (path != null) {
                return path.startsWith("/") ? path.substring(1) : path;
            }

        } catch (URISyntaxException e) {
            log.error("Issuer URL 格式不正確， issuer = {}", issuer);
            return "";
        }

        return "";
    }

    public <T> T get(Class<T> componentClass, String tenantId) {
        Map<Class<?>, Object> components = this.registry.get(tenantId);
        if (components != null) {
            Object component = components.get(componentClass);
            if (component != null) {
                log.debug("Found component {} for tenant '{}'", componentClass.getSimpleName(), tenantId);
                return componentClass.cast(component);
            } else {
                log.warn("Component type {} not found for tenant '{}' in registry.", componentClass.getSimpleName(), tenantId);
            }
        } else {
            log.warn("No components registered for tenant identifier '{}'", tenantId);
        }

        return null;
    }
}
