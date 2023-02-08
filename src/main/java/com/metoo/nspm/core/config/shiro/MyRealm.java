package com.metoo.nspm.core.config.shiro;

import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.shiro.salt.MyByteSource;
import com.metoo.nspm.core.shiro.tools.ApplicationContextUtils;
import com.metoo.nspm.entity.nspm.Res;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;

import java.util.List;

/**
 * 自定义Realm 将认证/授权数据来源设置为数据库的实现
 */
public class MyRealm extends AuthorizingRealm {

    @Autowired
    private IRoleService roleService;
    @Autowired
    private IResService resService;

    /**
     * 限定这个 Realm 只处理 UsernamePasswordToken
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;}

    // 授权
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

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String) authenticationToken.getPrincipal();
//        String password = new String((char[]) authenticationToken.getCredentials());
//        System.out.println("userName：" + username + " password：" + password);
        IUserService userService = (IUserService) ApplicationContextUtils.getBean("userServiceImpl");

        User user = userService.findByUserName(username);
        if(!ObjectUtils.isEmpty(user)){
            if(username.equals(user.getUsername())){
              /* Collection sessions = sess
                    if(username.equals(loginUsername)){  //这里的username也就是当前登录的username
                        session.setTimeout(0);  //这里就把session清除，ionDAO.getActiveSessions();
                for(Session scession: sessions){
                    String loginUsername = String.valueOf(session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY));//获得session中已经登录用户的名字

                    }
                }*/
                /**
                 * 将获取到的用户信息封装成AuthticationInfo对象返回，此处封装成SimpleAuthticationInfo对象
                 * 参数一：认证的实体信息，可以是从数据库中查询得到的实体类或用户名
                 * 参数二：查询获得的登陆密码(md5 + salt)
                 * 参数三：盐值(随即盐)
                 * 参数四：当前Realm对象的名称，直接调用父类的getName()方法即可
                 */
                String userName = user.getUsername();
                return new SimpleAuthenticationInfo(userName, user.getPassword(),  new MyByteSource(user.getSalt()), this.getName());
            }
        }
        return null;
    }

}
