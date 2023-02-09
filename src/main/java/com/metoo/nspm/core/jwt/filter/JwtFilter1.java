package com.metoo.nspm.core.jwt.filter;

import com.metoo.nspm.core.jwt.util.JwtToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 *
 * @description: SpringBoot基于Shiro整合Jwt无状态登录（认证授权）
 *
 * @author HKK
 *
 * @create 2023-02-09 15:30
 *
 */
public class JwtFilter1 extends BasicHttpAuthenticationFilter {

    /*
     * 过滤器执行流程：
     * isAccessAllowed()->isLoginAttempt()->executeLogin()
     */

    /**
     * 拦截器的前置  最先执行的 这里只做了一个跨域设置
     * */
    // 是否允许访问
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginAttempt(request, response)) {
            // 有认证意愿
            try {
                executeLogin(request, response);
                return true;
            } catch (Exception e) {
                // token错误
                responseError(response,e.getMessage());
            }
        }
        // 没有认证意愿（可能是登录行为或者为游客访问）,放行
        // 此处放行是因为有些操作不需要权限也可以执行，而对于那些需要权限才能执行的操作自然会因为没有token而在权限鉴定时被拦截
        return true;
    }

    // 是否有认证意愿（即是否携带token）
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("token");
        return token != null;
    }

    // 执行认证
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("token");
        JwtToken jwt = new JwtToken(token);
        // 使用自定义的JwtToken而不是默认的UsernamePasswordToken
        getSubject(request, response).login(jwt);
        // 调用了realm中的认证方法，没有出现异常则证明认证成功
        return true;
    }

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest req= (HttpServletRequest) request;
        HttpServletResponse res= (HttpServletResponse) response;
        res.setHeader("Access-control-Allow-Origin", req.getHeader("Origin"));
        res.setHeader("Access-control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        res.setHeader("Access-control-Allow-Headers", req.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (req.getMethod().equals(RequestMethod.OPTIONS.name())) {
            res.setStatus(HttpStatus.OK.value());
            // 返回true则继续执行拦截链，返回false则中断后续拦截，直接返回，option请求显然无需继续判断，直接返回
            return false;
        }
        return super.preHandle(request, response);
    }

    // 非法请求跳转
    private void responseError(ServletResponse response, String msg) {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        try {
            // msg封装为get请求的请求参数，即拼接在url后面，对于中文信息需要进行utf-8编码
            msg = URLEncoder.encode(msg, String.valueOf(StandardCharsets.UTF_8));
            // 跳转至控制器unauthorized
            httpServletResponse.sendRedirect("/admin/auth/403" + msg);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
