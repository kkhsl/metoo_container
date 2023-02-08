package com.metoo.nspm.core.utils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>
 *     Title: ShiroFilterUtils.java
 * </p>
 *
 * <p>
 *     Description:
 * </p>
 */
public class ShiroFilterUtils {
    final static Class<? extends ShiroFilterUtils> CLAZZ = ShiroFilterUtils.class;
    //登录页面
    static final String LOGIN_URL = "/u/login";
    //没有授权提醒
    static final String UNAUTHORIZED = "/open/unauthorized";

    /**
     *      *是否是Ajax请求,如果是ajax请求响应头会有，x-requested-with
     *      * @param request
     *      * @return
     *     
     */
    public static boolean isAjax(ServletRequest request) {
        return "XMLHttpRequest".equalsIgnoreCase(((HttpServletRequest) request).getHeader("X-Requested-With"));
    }

    /**
     *      * response 设置超时
     *      * @param hresponse
     *      * @param resultMap
     *      * @throws IOException
     *     
     */
    public static void out(ServletResponse servletResponse) {
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        response.setCharacterEncoding("UTF-8");
        //在响应头设置session状态
        response.setHeader("session-status", "timeout");
    }

}
