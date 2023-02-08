package com.metoo.nspm.core.utils;

import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class CookieUtil {


    /**
     * 移除指定cookie
     * @param request
     * @param response
     * @param name
     */
    public static void removeCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        if (null != name) {
            Cookie cookie = getCookie(request, name);
            if (null != cookie) {
                cookie.setPath("/");
                cookie.setValue("");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }
    }

    public static Cookie getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length >= 1) {
            Cookie cookie = null;
            Cookie[] var4 = cookies;
            int var5 = cookies.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                Cookie c = var4[var6];
                if (name.equals(c.getName())) {
                    cookie = c;
                    break;
                }
            }

            return cookie;
        } else {
            return null;
        }
    }

}
