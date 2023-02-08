package com.metoo.nspm.core.shiro.main;

//import com.metoo.nspm.core.config.shiro.MyRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;

public class ShrioCustomerRealmManager {

    public static void main(String[] args)throws Exception {
        //1、创建安全管理器SecurityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        // 2，给安全管理器设置自定义Realm
//        securityManager.setRealm(new MyRealm());
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

    }
}
