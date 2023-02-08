package com.metoo.nspm.core.jwt.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.metoo.nspm.core.jwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *     Title: JwtInterceptor.java
 * </p>
 *
 * <p>
 *     Description: JWT 登录拦截器
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */
@Component
public class JwtInterceptor implements HandlerInterceptor {

    // 预处理回调方法
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("token");
        Map map = new HashMap();
        int code = 200;
        try {
            JwtUtil.verifyJwt(token);// 验证令牌
            return true;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg","无效签名" );
            code = 501;
            System.out.println("无效签名");
        }catch (TokenExpiredException e){
            e.printStackTrace();
            code = 502;
            map.put("msg","token 过期" );
            System.out.println("token 过期");
        }catch (AlgorithmMismatchException e){
            e.printStackTrace();
            code = 503;
            map.put("msg","算法不一致" );
            System.out.println("算法不一致");
        }catch (Exception e){
            e.printStackTrace();
            code = 504;
            map.put("msg","token 无效" );
            System.out.println("token 无效");
        }
        map.put("code", code );
        String json  = new ObjectMapper().writeValueAsString(map);
        response.setContentType("application/json;charset=UTF-8");
        //response.getWriter().print(json);
        return false;
    }
}
