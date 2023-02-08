package com.metoo.nspm.core.shiro.main;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;

public class ShiroManagerAction2 {

    public static void main(String[] args)throws Exception {
        //1、创建安全管理器SecurityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        // 2，给安全管理器设置Realm
        securityManager.setRealm(new IniRealm("classpath:shiro_users.ini"));
        //3、SecurityUtils给全局工具类设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);
        //4、创建Subject主体
        Subject subject = SecurityUtils.getSubject();

        //5、创建账号密码登录方式的令牌Token
        UsernamePasswordToken token = new UsernamePasswordToken("admin","123");

        try {
            //6、用户认证(shiro的核心功能之一)
            System.out.println("认证状态：" + subject.isAuthenticated());
            subject.login(token);// 用户认证
            System.out.println("认证状态：" + subject.isAuthenticated());
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }

        //7、安全退出
//        subject.logout();

        //8、角色认证
//        第一种方式：
        if (subject.hasRole("role12")) {
            System.out.println("角色验证成功！");
        } else {
            System.out.println("角色验证失败！");
        }

//        第二种方式：
        subject.checkRole("role2");
        System.out.println("角色验证成功！");


        //7、安全推出
        subject.logout();

        //9、权限验证
//        第一种方式：
        if (subject.isPermitted("system:user:add")) {
            System.out.println("权限验证成功！");
        } else {
            System.out.println("权限验证失败！");
        }

//        第二种方式：
        subject.checkPermission("system:w:wd");
        System.out.println("权限验证成功！");

        //7、安全推出
        subject.logout();
    }
}

