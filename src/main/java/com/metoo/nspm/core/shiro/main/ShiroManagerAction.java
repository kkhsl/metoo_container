package com.metoo.nspm.core.shiro.main;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.mgt.SecurityManager;

public class ShiroManagerAction {

    public static void main(String[] args)throws Exception {
        //1、创建SecurityManagerFactory,用于读取加载安全的数据源
        IniSecurityManagerFactory factory
                = new IniSecurityManagerFactory("classpath:shiro-permission.ini");

        //2、创建安全管理器SecurityManager
        // 方式一：
        SecurityManager securityManager = factory.getInstance();
        // 方式二：
//        SecurityManager securityManager = new DefaultSecurityManager();

        //3、将SecurityManager交由SecurityUtils来管理
        SecurityUtils.setSecurityManager(securityManager);

        //4、创建Subject主体
        Subject subject = SecurityUtils.getSubject();

        //5、创建账号密码登录方式的令牌Token
        UsernamePasswordToken token = new UsernamePasswordToken("admin","123");

        //6、用户认证(shiro的核心功能之一)
        subject.login(token);
        System.out.println("用户认证成功！");

        //7、安全推出
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

