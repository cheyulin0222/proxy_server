package com.arplanets.auth.utils;

import eu.bitwalker.useragentutils.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

public class ClientInfoUtil {

    public static String getClientIp(HttpServletRequest request) {
        String ip = null;

        // 嘗試從各種標頭中獲取IP地址
        String[] headers = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headers) {
            ip = request.getHeader(header);
            if (isValidIp(ip)) {
                break;
            }
        }

        // 如果所有標頭都沒有有效的IP，使用遠程地址
        if (!isValidIp(ip)) {
            ip = request.getRemoteAddr();
        }

        // 處理X-Forwarded-For中包含多個IP的情況，取第一個非unknown的IP
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        // 如果是本地測試，顯示為127.0.0.1
        if ("0:0:0:0:0:0:0:1".equals(ip)) {
            ip = "127.0.0.1";
        }

        return ip;
    }

    /**
     * 獲取用戶代理信息
     *
     * @param request HTTP請求
     * @return 包含設備類型、操作系統和版本的Map
     */
    public static Map<String, String> getClientInfo(HttpServletRequest request) {
        Map<String, String> clientInfo = new HashMap<>();

        String userAgentString = request.getHeader("User-Agent");
        if (userAgentString != null) {
            UserAgent userAgent = UserAgent.parseUserAgentString(userAgentString);
            OperatingSystem os = userAgent.getOperatingSystem();
            Browser browser = userAgent.getBrowser();

            // 獲取設備類型
            DeviceType deviceType = os.getDeviceType();
            clientInfo.put("deviceType", getDeviceTypeString(deviceType));

            // 獲取操作系統名稱
            clientInfo.put("osName", os.getName());

            // 獲取操作系統版本
            clientInfo.put("osVersion", getOsVersion(os, userAgentString));

            // 額外信息，如需要也可以獲取
            clientInfo.put("browserName", browser.getName());
            clientInfo.put("browserVersion", getBrowserVersion(userAgent, userAgentString));
        } else {
            // 如果沒有User-Agent頭，則設置為未知
            clientInfo.put("deviceType", "Unknown");
            clientInfo.put("osName", "Unknown");
            clientInfo.put("osVersion", "Unknown");
        }

        return clientInfo;
    }

    /**
     * 獲取設備類型的友好名稱
     */
    private static String getDeviceTypeString(DeviceType deviceType) {
        if (deviceType == DeviceType.COMPUTER) {
            return "Desktop";
        } else if (deviceType == DeviceType.MOBILE) {
            return "Mobile";
        } else if (deviceType == DeviceType.TABLET) {
            return "Tablet";
        } else {
            return "Unknown";
        }
    }

    /**
     * 嘗試獲取操作系統版本
     * 注意：UserAgent庫不總是能準確提取版本號，此方法嘗試處理常見情況
     */
    private static String getOsVersion(OperatingSystem os, String userAgentString) {
        // 根據操作系統類型嘗試提取版本號
        if (os.getGroup() == OperatingSystem.WINDOWS) {
            return extractWindowsVersion(userAgentString);
        } else if (os.getGroup() == OperatingSystem.MAC_OS) {
            return extractMacVersion(userAgentString);
        } else if (os.getGroup() == OperatingSystem.ANDROID) {
            return extractAndroidVersion(userAgentString);
        } else if (os.getGroup() == OperatingSystem.IOS) {
            return extractIOSVersion(userAgentString);
        }

        // 對於其他操作系統，返回製造商信息
        return os.getManufacturer().getName();
    }

    /**
     * 提取Windows操作系統版本
     */
    private static String extractWindowsVersion(String userAgent) {
        if (userAgent.contains("Windows NT 10.0")) {
            return "10";
        } else if (userAgent.contains("Windows NT 6.3")) {
            return "8.1";
        } else if (userAgent.contains("Windows NT 6.2")) {
            return "8";
        } else if (userAgent.contains("Windows NT 6.1")) {
            return "7";
        } else if (userAgent.contains("Windows NT 6.0")) {
            return "Vista";
        } else if (userAgent.contains("Windows NT 5.1") || userAgent.contains("Windows XP")) {
            return "XP";
        } else {
            return "Unknown";
        }
    }

    /**
     * 提取Mac OS版本
     */
    private static String extractMacVersion(String userAgent) {
        int startIndex = userAgent.indexOf("Mac OS X ");
        if (startIndex > -1) {
            int endIndex = userAgent.indexOf(")", startIndex);
            if (endIndex > -1) {
                String version = userAgent.substring(startIndex + 9, endIndex);
                // 替換下劃線為點
                return version.replace("_", ".");
            }
        }
        return "Unknown";
    }

    /**
     * 提取Android版本
     */
    private static String extractAndroidVersion(String userAgent) {
        int startIndex = userAgent.indexOf("Android ");
        if (startIndex > -1) {
            int endIndex = userAgent.indexOf(";", startIndex);
            if (endIndex > -1) {
                return userAgent.substring(startIndex + 8, endIndex);
            }
        }
        return "Unknown";
    }

    /**
     * 提取iOS版本
     */
    private static String extractIOSVersion(String userAgent) {
        int startIndex = userAgent.indexOf("OS ");
        if (startIndex > -1 && userAgent.contains("like Mac OS X")) {
            int endIndex = userAgent.indexOf(" like", startIndex);
            if (endIndex > -1) {
                String version = userAgent.substring(startIndex + 3, endIndex);
                return version.replace("_", ".");
            }
        }
        return "Unknown";
    }

    /**
     * 獲取瀏覽器版本
     */
    private static String getBrowserVersion(UserAgent userAgent, String userAgentString) {
        Version version = userAgent.getBrowserVersion();
        if (version != null && version.getVersion() != null) {
            return version.getVersion();
        }

        // 如果庫無法解析版本，嘗試基本提取
        Browser browser = userAgent.getBrowser();
        if (browser != null) {
            int startIndex = userAgentString.indexOf(browser.getName() + "/");
            if (startIndex > -1) {
                startIndex += browser.getName().length() + 1;
                int endIndex = userAgentString.indexOf(" ", startIndex);
                if (endIndex > -1) {
                    return userAgentString.substring(startIndex, endIndex);
                } else {
                    return userAgentString.substring(startIndex);
                }
            }
        }

        return "Unknown";
    }

    private static boolean isValidIp(String ip) {
        return ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip);
    }
}
