package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IRoleResService;
import com.metoo.nspm.entity.nspm.RoleRes;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("role/res")
public class RoleResManagerController {

    @Autowired
    private IRoleResService roleResService;

//    @RequiresPermissions("ADMIN:ROLEPERMISSION:SETSYSRIGHTS")
    @ApiOperation("角色分配权限")
    @PostMapping("/SetSysRights")
    public Object SetSysRights(Long role_id, String res_id){
        List<RoleRes> roleResList = new ArrayList<RoleRes>();
        this.roleResService.deleteRoleResByRoleId(role_id);
        String[] res_ids = res_id.split(",");
        for(String id : res_ids){
            roleResList.add(new RoleRes(role_id, Long.parseLong(id)));
        }
        boolean flag = this.roleResService.batchAddRoleRes(roleResList);
        return null;
    }

}
