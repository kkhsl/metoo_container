package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IRoleGroupService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.RoleGroupDto;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.RoleGroup;
import com.metoo.nspm.req.RoleGroupReq;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("角色组")
@RestController
@RequestMapping("/admin/role_group")
public class RoleGroupManagerController {

    @Autowired
    private IRoleGroupService roleGroupService;
    @Autowired
    private IRoleService roleService;

//    @RequiresPermissions("ADMIN:ROLEGROUP:LIST")
//    @ApiOperation("角色组列表")
//    @PostMapping("/list")
//    public Object list(@RequestBody RoleGroupDto dto){
//        Map data = new HashMap();
//        if(dto.getCurrentPage() == null || dto.getCurrentPage().equals("")){
//            dto.setCurrentPage(1);
//        }
//        if(dto.getPageSize() == null || dto.getPageSize().equals("")){
//            dto.setPageSize(15);
//        }
//        Map<String, Integer> params = new HashMap<String, Integer>();
//        params.put("pageSize", dto.getPageSize());
//        params.put("currentPage", (dto.getCurrentPage() ) );
//        Page<RoleGroup> page = this.roleGroupService.query(params);
//        data.put("data", page.getResult());
//        data.put("currentPage", dto.getCurrentPage());
//        data.put("pageSize", page.getPageSize());
//        data.put("pages", page.getPages());
//        return ResponseUtil.query(data);
//    }


    @ApiOperation("角色组列表/角色")
    @PostMapping("/group/roles")
    public Object roleGroup(Integer currentPage, Integer pageSize){
        Map data = new HashMap();
        if(currentPage == null || currentPage < 1){
            currentPage = 0;
        }
        if(pageSize == null || pageSize < 1 ){
            pageSize = 15;
        }
        Map<String, Integer> params = new HashMap<String, Integer>();
        params.put("currentPage", currentPage);
        params.put("pageSize", pageSize);
        data.put("currentPage", currentPage);
        List<RoleGroup> roleGroupList = this.roleGroupService.roleUnitGroup(params);
        data.put("data", roleGroupList);
        data.put("pageSize", roleGroupList.size());
        return ResponseUtil.query(data);
    }

//    @RequiresPermissions("ADMIN:ROLEGROUP:ADD")
    @ApiOperation("角色组添加")
    @GetMapping("/add")
    public Object add(){
        // 查询所有角色
        List<Role> roles = this.roleService.findRoleByType("ADMIN");
        return ResponseUtil.ok(roles);
}

//    @RequiresPermissions("ADMIN:ROLEGROUP:UPDATE")
    @ApiOperation("角色组更新")
    @PostMapping("/update")
    public Object update(@RequestBody RoleGroupReq req){
       RoleGroup roleGroup = this.roleGroupService.change(req.getId());
        if(roleGroup != null){
           return ResponseUtil.ok(this.roleGroupService.update(roleGroup));
        }
        return ResponseUtil.badArgument();
    }

//    @RequiresPermissions("ADMIN:ROLEGROUP:SAVE")
    @ApiOperation("角色组保存")
    @PostMapping("/save")
    public Object save(@RequestBody  RoleGroupDto dto){
        RoleGroup roleGroup = this.roleGroupService.getObjById(dto.getId());
        if(dto.getName() == null){
            return ResponseUtil.badArgument();
        }
        // 查询当前组是否存在
        if(roleGroup == null){
            if(this.roleGroupService.checkExist(dto.getName())){
                return ResponseUtil.fail(400, "RoleGroup is exists");
            }
        }
        if(this.roleGroupService.save(dto)){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

//    @RequiresPermissions("ADMIN:ROLEGROUP:DELETE")
    @ApiOperation("角色组删除")
    @RequestMapping("/delete")
    public Object delete(@RequestBody RoleGroupDto dto){
        List<Role> roleList = this.roleService.findRoleByRoleGroupId(dto.getId());
        if(roleList.size() > 0){
            return ResponseUtil.fail("Remove the associated role first");
        }
        if(this.roleGroupService.delete(dto.getId()) != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }
}
