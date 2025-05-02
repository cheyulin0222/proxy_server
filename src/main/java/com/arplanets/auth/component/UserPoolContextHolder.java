package com.arplanets.auth.component;


public class UserPoolContextHolder {

    private static final ThreadLocal<UserPoolContext> contextHolder = new ThreadLocal<>();

    public static void setContext(UserPoolContext context) {
        contextHolder.set(context);
    }

    public static UserPoolContext getContext() {
        return contextHolder.get();
    }

    public static void clearContext() {
        contextHolder.remove();
    }
}
