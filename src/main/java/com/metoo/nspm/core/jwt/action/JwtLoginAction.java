package com.metoo.nspm.core.jwt.action;

import com.metoo.nspm.core.jwt.util.JwtUtil;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *     Title: JwtLoginAction
 * </p>
 *
 * <p>
 *     Description: Spring Boot 集成 JWT
 *     SpringWeb项目：在拦截器中拦截登录请求；
 *     SpeingCloud项目：在网关中拦截登录请求；
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */
@RestController
@RequestMapping("/jwt")
public class JwtLoginAction {

    @Autowired
    private IUserService userService;

    @RequestMapping("login")
    public Object login(HttpServletResponse response, User user) throws IOException {
        //this.userService.
            Map payload = new HashMap();
        payload.put("username", user.getUsername());
        String token = JwtUtil.getToken(payload);
        response.setHeader("token", token);
//        response.getWriter().print("TestResponse");

        return token;
    }

    @RequestMapping("/test/filter")
    public Object test_filter(HttpServletRequest request, HttpServletResponse response){
        return ResponseUtil.ok("ok");
    }


}
