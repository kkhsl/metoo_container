package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.service.nspm.IRegisterService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.core.service.nspm.IUserRoleService;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.entity.nspm.UserRole;
import com.metoo.nspm.vo.Result;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/buyer/")
public class RegisterController {

    @Autowired
    private IRegisterService registerService;
    @Autowired
    private IRoleService roleService;
    @Autowired
    private IUserRoleService userRoleService;

    /**
     * 用户注册
     *
     * @param user
     * @return
     */
    @RequestMapping("/register")
    public Object register(User user) {
        try {
            boolean object = this.verify_username(user.getUsername());
            if (object) {
                user.setAddTime(new Date());
                user.setUserRole("BUYER");
                user.setSex(-1);
                int flag = this.registerService.register(user);
                //分配角色权限
                List<Role> roles = this.roleService.findRoleByType("BUYER");

                if (!CollectionUtils.isEmpty(roles)) {
                    List<UserRole> userRoles = new ArrayList<UserRole>();
                   /*roles.forEach(role -> {
                       UserRole userRole = new UserRole();
                       userRole.setUser_id(user.getId());
                       userRole.setRole_id(role.getId());
                       userRoles.add(userRole);
                   });*/
                    User obj = this.registerService.findByUsername(user.getUsername());
                   for(Role role:roles){
                       UserRole userRole = new UserRole();
                       userRole.setUser_id(obj.getId());
                       userRole.setRole_id(role.getId());
                       userRoles.add(userRole);
                   }
                    int role_flag = this.userRoleService.batchAddUserRole(userRoles);
                }

                return new Result(200, "Registered successfully");
            } else {
                return new Result(400, "The account already exists.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new Result(500, "registered error");
        }
    }


    /**
     * 根据用户名查询用户是否已注册
     *
     * @param username
     * @return
     */
    public boolean verify_username(String username) {
        boolean flag = true;
        if (!username.equals("")) {
            User object = this.registerService.findByUsername(username);
            if (object != null) {
                flag = false;
            }
        }
        return flag;
    }
}
