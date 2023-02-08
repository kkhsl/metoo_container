package com.metoo.nspm.core.jwt.action;

import com.metoo.nspm.core.jwt.util.JwtToken;
import com.metoo.nspm.core.jwt.util.JwtUtil;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.vo.Result;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
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

    @RequestMapping("/login/test")
    public Object login(HttpServletResponse response, User user) throws IOException {

        Map payload = new HashMap();
        payload.put("username", user.getUsername());
        String token = JwtUtil.getToken(payload);
        response.setHeader("token", token);
//        response.getWriter().print("TestResponse");

        return token;
    }

    @ApiOperation("登录（两个realm）")
    @RequestMapping("/login")
    public Object login(HttpServletRequest request, HttpServletResponse response,
                        String username, String password, @ApiParam("验证码") String captcha, String isRememberMe){
        String msg = "";
        // 通过安全工具类获取 Subject
        Subject subject = SecurityUtils.getSubject();

        // 获取当前已登录用户
        Session session = SecurityUtils.getSubject().getSession();
        String sessionCaptcha = (String) session.getAttribute("captcha");
        session.getStartTimestamp();
        if(StringUtils.isEmpty(username)){
            return ResponseUtil.badArgument("用户名必填");
        }
        if(StringUtils.isEmpty(password)){
            return ResponseUtil.badArgument("密码必填");
        }
        if(StringUtils.isEmpty(captcha)){
            return ResponseUtil.badArgument("验证码必填");
        }
        if(!org.springframework.util.StringUtils.isEmpty(captcha) && !StringUtils.isEmpty(sessionCaptcha)){
            if(sessionCaptcha.toUpperCase().equals(captcha.toUpperCase())){
                boolean flag = true;// 当前用户是否已登录
                if(subject.getPrincipal() != null && subject.isAuthenticated()){
                    String userName = subject.getPrincipal().toString();
                    if(userName.equals(username)){
                        flag = false;
                    }
                }
                if(flag){
                    UsernamePasswordToken token = new UsernamePasswordToken(username,password);
                    try {
                        if(isRememberMe != null && isRememberMe.equals("1")){
                            token.setRememberMe(true);
                            // 或 UsernamePasswordToken token = new UsernamePasswordToken(username,password,true);
                        }else{
                            token.setRememberMe(false);
                        }
                        subject.login(token);
                        session.removeAttribute("captcha");
                        User user = this.userService.findByUserName(username);
//
                        //  return "redirect:/index.jsp";
                        Map payload = new HashMap();
                        payload.put("username", user.getUsername());
                        String jwtToken = JwtUtil.getToken(payload);
                        response.setHeader("token", jwtToken);
                        return ResponseUtil.ok(user.getId());
                    } catch (UnknownAccountException e) {
                        e.printStackTrace();
                        msg = "用户名错误";
                        System.out.println("用户名错误");
                        return new Result(410, msg);
                    } catch (IncorrectCredentialsException e){
                        e.printStackTrace();
                        msg = "密码错误";
                        System.out.println("密码错误");
                        return new Result(420, msg);
                    }
                }else{
                    return new Result(200, "用户已登录");
                }
            }else{
                return new Result(430, "验证码错误");
            }
        }else{
            return new Result(400,  "Captcha has expired");
        }
    }


    @GetMapping("/whoami")
    public Map whoami(){
        JwtToken jwtUser = (JwtToken) SecurityUtils.getSubject().getPrincipal();

        Map<String,String> res=new HashMap<>();
        res.put("result","you are "+jwtUser);
//        res.put("token",JwtUtil.getToken());

        return res;
    }

    @RequestMapping("/test/filter")
    public Object test_filter(HttpServletRequest request, HttpServletResponse response){
        return ResponseUtil.ok("ok");
    }


}
