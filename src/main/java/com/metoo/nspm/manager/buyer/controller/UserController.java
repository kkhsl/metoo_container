package com.metoo.nspm.manager.buyer.controller;

import com.metoo.nspm.core.service.nspm.IRegisterService;
import com.metoo.nspm.entity.nspm.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private IRegisterService registerService;

    @RequestMapping("/register")
    public String register(User user){
        try {
            System.out.println("===sssss========");
            this.registerService.register(user);
            System.out.println("===========");
            return "redirect:/login.jsp";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/register.jsp";
        }
    }

    @RequestMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response, String username, String password){
        // 通过安全工具类获取 Subject
        Subject subject = SecurityUtils.getSubject();

        // 获取当前已登录用户
        //User user = (User) SecurityUtils.getSubject().getPrincipal();

      /*  String username = request.getParameter("username");
        String password = request.getParameter("password");*/
       /* String sale = SaltUtils.getSalt(8);
        Md5Hash md5Hash = new Md5Hash(password, sale, 1024);*/
        UsernamePasswordToken token = new UsernamePasswordToken(username,password);

        try {
            subject.login(token);
            return "redirect:/index.jsp";
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("用户名错误");
        } catch (IncorrectCredentialsException e){
            e.printStackTrace();
            System.out.println("密码错误");
        }
        return "redirect:/login.jsp";
    }

    @RequestMapping("/logout")
    public String logout(){
        Subject subject = SecurityUtils.getSubject();

        subject.logout(); // 退出登录

        return "redirect:/login.jsp";
    }

    /**
     * 生成图片验证码
     */
    @RequestMapping("/getImage")
    public void getImage(HttpServletRequest request, HttpServletResponse response){

    }

    /**
     * 测试登录 SessionID
     */
  /*  @RequestMapping("test_login")
    public String testLogin(HttpServletRequest request, HttpServletResponse response, String username, String password){
        if("hkk".equals(username)){
            return "redirect:/index.jsp";
        }else{
            return "redirect:/index.jsp";
        }
    }*/


}
