package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.RoleDto;
import com.metoo.nspm.entity.nspm.Res;
import com.metoo.nspm.entity.nspm.Role;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("角色管理")
@RestController
@RequestMapping("/admin/role")
public class RoleManagerController {

    @Autowired
    private IRoleService roleService;
    @Autowired
    private IResService resService;

    @RequiresPermissions("LK:ROLE:MANAGER")
    @ApiOperation("角色列表")
    @RequestMapping("/list")
    public Object list(@RequestBody RoleDto dto){
        Map data = new HashMap();
        Page<Role> page = this.roleService.query(dto);
        if(page.getResult().size() > 0){
            return  ResponseUtil.ok(new PageInfo<Role>(page));
        }
       return ResponseUtil.ok();
    }

    @RequiresPermissions("LK:ROLE:MANAGER")
    @ApiOperation("角色添加")
    @GetMapping("/add")
    public Object add(){
        Map data = new HashMap();
    /*    List<RoleGroup> roleGroupList = this.roleGroupService.selectByPrimaryType("ADMIN");
        map.put("roleGroupList", roleGroupList);
        Map params = new HashMap();
        params.put("currentPage", 1);
        params.put("pageSize", 1000);
        List<Res> resList = this.resService.findPermissionByMap(params);
        map.put("resList", resList);*/
        Map params = new HashMap();
        params.put("currentPage", 0);
        params.put("pageSize", 10000);
        List<Res> ResList = this.resService.findPermissionByJoin(params);
        data.put("obj", ResList);
        return ResponseUtil.ok(data);
    }
  /*  public Object add(){
        Map map = new HashMap();
        List<RoleGroup> roleGroupList = this.roleGroupService.selectByPrimaryType("ADMIN");
        map.put("roleGroupList", roleGroupList);
        Map params = new HashMap();
        params.put("currentPage", 1);
        params.put("pageSize", 1000);
        List<Res> resList = this.resService.findPermissionByMap(params);
        map.put("resList", resList);
        return ResponseUtil.ok(map);
    }*/

   /* @ApiOperation("角色添加")
    @GetMapping("/add")
    public Object add(){
        Map map = new HashMap();
        // 查询角色组
        List<RoleGroup> roleGroupList = this.roleGroupService.selectByPrimaryType("ADMIN");
        map.put("roleGroup", roleGroupList);
        return ResponseUtil.ok();
    }*/

    @RequiresPermissions("LK:ROLE:MANAGER")
    @ApiOperation("角色修改/回显")
    @PostMapping("/update")
     public Object udpate(@RequestBody RoleDto dto){
        Role role = this.roleService.findRoleById(dto.getId());
        if(role != null){
            Map data =  new HashMap();
            data.put("obj", this.roleService.selectByPrimaryUpdae(dto.getId()));
            // 是否改为idList
           // data.put("roleResList", this.resService.findResByRoleId(role.getId()));
            Map params = new HashMap();
            params.put("currentPage", 0);
            params.put("pageSize", 10000);
            List<Res> resList = this.resService.findPermissionByJoin(params);
            data.put("resList", resList);
            return ResponseUtil.ok(data);
        }
        return ResponseUtil.badArgument();
    }
   /* public Object udpate(@RequestBody RoleDto dto){
        Role role = this.roleService.findRoleById(dto.getId());
        if(role != null){
            Map map =  new HashMap();
            map.put("obj", this.roleService.selectByPrimaryUpdae(dto.getId()));
            map.put("roleGroupList", this.roleGroupService.selectByPrimaryType("ADMIN"));
            map.put("roleResList", this.resService.findResByRoleId(role.getId()));
            Map params = new HashMap();
            params.put("currentPage", 1);
            params.put("pageSize", 1000);
            List<Res> resList = this.resService.findPermissionByMap(params);
            map.put("resList", resList);
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument();
    }*/

    @RequiresPermissions("LK:ROLE:MANAGER")
    @ApiOperation("角色保存")
    @PostMapping("/save")
    public Object save(@RequestBody RoleDto dto){
        if(dto.getName() != null){
            Role role = this.roleService.findObjByName(dto.getName());
            Role role2 = this.roleService.findRoleById(dto.getId());
            boolean flag = true;
            if(role != null){
                flag = false;
                if(role2 != null){
                    if(!role.getName().equals(role2.getName())){
                        flag =  false;
                    }else{
                        flag = true;
                    }
                }
            }

            if(flag){
                if(this.roleService.save(dto)){
                    return ResponseUtil.ok();
                }
            }
            return ResponseUtil.badArgument("角色已存在");
        }
        return ResponseUtil.badArgument("请输入角色名称");
    }

    /*@ApiOperation("角色删除")
    @PostMapping("/delete")
    public Object delete(Long id){
        Role role = this.roleService.findRoleById(id);
        if(role != null){
            RoleDto roleDto = new RoleDto();
            role.setRoleGroup(null);
            BeanUtils.copyProperties(role, roleDto);
            this.roleService.save(roleDto);
            if(this.roleService.delete(role.getId())){
                return ResponseUtil.ok();
            }
            return ResponseUtil.delete();
        }
        return ResponseUtil.badArgument();
    }*/

    @RequiresPermissions("LK:ROLE:MANAGER")
    @ApiOperation("角色删除")
    @RequestMapping("/delete")
    public Object delete(@RequestBody RoleDto dto){
        Role role = this.roleService.findRoleById(dto.getId());
        if(role != null){
            // 根据角色ID查询权限
            List<Res> resList =  this.resService.findResByRoleId(role.getId());
            if(resList.size() > 0){
                return ResponseUtil.fail("已有用户关联当前角色，禁止删除");
            }
            if(this.roleService.delete(role.getId())){
                return ResponseUtil.ok();
            }
        }
        return ResponseUtil.delete();
    }
}
