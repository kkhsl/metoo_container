package com.metoo.nspm.core.jwt.util;

import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.shiro.tools.ApplicationContextUtils;
import com.metoo.nspm.entity.nspm.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class JwtUserHolder {

    @Autowired
    private IUserService userService;

    public static User currentUser() {
        if (SecurityUtils.getSubject() != null){
            Subject subject = SecurityUtils.getSubject();
            if(subject.getPrincipal() != null && subject.isAuthenticated()){
                String token = SecurityUtils.getSubject().getPrincipal().toString();
                IUserService userService = (IUserService) ApplicationContextUtils.getBean("userServiceImpl");
                User user = userService.findByUserName(JwtUtil.getClaimFiled(token, "username"));
                if(user != null){
                    return user;
                }
            }
        }

        return null;
    }

}
