package com.metoo.nspm.core.jwt.config;

import com.metoo.nspm.core.jwt.util.JwtToken;
import com.metoo.nspm.core.service.nspm.IRegisterService;
import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.shiro.salt.MyByteSource;
import com.metoo.nspm.core.shiro.tools.ApplicationContextUtils;
import com.metoo.nspm.entity.nspm.Res;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.List;

/**
 * JwtRealm 只负责校验 JwtToken
 */
@Component
public class JwtRealm extends AuthorizingRealm {

    @Autowired
    private IRoleService roleService;
    @Autowired
    private IResService resService;

    /**
     * 限定这个 Realm 只处理我们自定义的 JwtToken
     */
    @Override
    public boolean supports(AuthenticationToken token) {

        return token instanceof JwtToken;
    }


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();
        System.out.println("userName：" + username);
        IUserService userService = (IUserService) ApplicationContextUtils.getBean("userServiceImpl");
        User user = userService.findByUserName(username);
        List<Role> roles = this.roleService.findRoleByUserId(user.getId());//user.getRoles();
        if(!CollectionUtils.isEmpty(roles)){
            if(user != null){
                SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
                for(Role role : roles){
                    simpleAuthorizationInfo.addRole(role.getRoleCode());
                    List<Res> permissions = resService.findResByRoleId(role.getId());
                    if(!CollectionUtils.isEmpty(permissions)){
                        permissions.forEach(permission -> {
                            simpleAuthorizationInfo.addStringPermission(permission.getValue());
                        });
                    }
                }
                return simpleAuthorizationInfo;
            }
        }
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken) throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) authcToken;
        if (jwtToken.getPrincipal() == null) {
            throw new AccountException("JWT token参数异常！");
        }
        // 从 JwtToken 中获取当前用户
        String username = jwtToken.getPrincipal().toString();
        // 查询数据库获取用户信息
        IUserService userService = (IUserService) ApplicationContextUtils.getBean("userServiceImpl");
        User user = userService.findByUserName(username);

        // 用户不存在
        if (user == null) {
            throw new UnknownAccountException("用户不存在！");
        }

        // 用户被锁定
        if (user.isLocked()) {
            throw new LockedAccountException("该用户已被锁定,暂时无法登录！");
        }

        String token = jwtToken.getCredentials();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(jwtToken, token, getName());
//        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username, user.getPassword(),  new MyByteSource(user.getSalt()), this.getName());
        return info;
    }
}
