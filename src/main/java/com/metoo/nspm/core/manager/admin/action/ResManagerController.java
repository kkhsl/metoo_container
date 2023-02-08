package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.ResDto;
import com.metoo.nspm.entity.nspm.Res;
import com.github.pagehelper.util.StringUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("权限管理")
@RestController
@RequestMapping("/admin/permission")
public class ResManagerController {

    @Autowired
    private IResService resService;


 /*   public Object list(@RequestBody ResDto dto){
        Map data = new HashMap();
        if(dto.getCurrentPage() == null || dto.getCurrentPage().equals("")){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null || dto.getPageSize().equals("")){
            dto.setPageSize(15);
        }
        Map params = new HashMap();
        params.put("currentPage", (dto.getCurrentPage()));
        params.put("pageSize", dto.getPageSize());
        Page<Res> page = this.resService.query(params);
        data.put("obj", page.getResult());
        data.put("total", page.getTotal());
        data.put("currentPage", page.getPageNum());
        data.put("pageSize", page.getPageSize());
        data.put("pages", page.getPages());

        return ResponseUtil.ok(data);
    }*/

    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @ApiOperation("权限列表")
    @PostMapping("/list")
    public Object list(@RequestBody ResDto dto) {
        Map data = new HashMap();
        if (dto == null) {
            dto = new ResDto();
        }
        if(dto.getCurrentPage() < 1){
            dto.setCurrentPage(0);
        }
        Map params = new HashMap();
        params.put("currentPage", dto.getCurrentPage() - 1);
        params.put("pageSize", dto.getPageSize());
        List<Res> ResList = this.resService.findPermissionByJoin(params);
        data.put("obj", ResList);
        data.put("currentPage", dto.getCurrentPage());
        data.put("pageSize", ResList.size());
        return ResponseUtil.ok(data);
     }
    /*public Object list(@RequestBody ResDto dto){
        if(dto.getCurrentPage() == null || dto.getCurrentPage().equals("")){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null || dto.getPageSize().equals("")){
            dto.setPageSize(15);
        }
        Map params = new HashMap();
        params.put("startRow", (dto.getCurrentPage()) * dto.getPageSize());
        params.put("pageSize", dto.getPageSize());
        return ResponseUtil.ok(this.resService.query(params));
    }*/

    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @ApiOperation("权限添加")
    @PostMapping("/add")
    public Object add(){
        Map data = new HashMap();
        // 查询所有父级
        Map params = new HashMap();
        params.put("level", 0);
        List<Res> parentList = this.resService.findPermissionByMap(params);
        data.put("parentList", parentList);
        return ResponseUtil.ok(data);
    }

    /*public Object add(){
        List<Role> roles = this.roleService.findRoleByType("ADMIN");
        return ResponseUtil.ok(roles);
    }*/

    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @ApiOperation("权限更新")
    @PostMapping("/update")
    public Object update(@RequestBody ResDto dto){
        Map data = new HashMap();
        Res res = this.resService.findResUnitRoleByResId(dto.getId());
        if(res != null){
            data.put("obj", res);
            // 查询所有父级
            Map params = new HashMap();
            params.put("level", 0);
            List<Res> parentList = this.resService.findPermissionByMap(params);
            data.put("parentList", parentList);
           /* List<Role> roles = this.roleService.findRoleByType("ADMIN");
            data.put("roles", roles);*/
            return ResponseUtil.ok(data);
        }
        return ResponseUtil.badArgument();
    }

//    @ApiOperation("权限信息查询")
    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @RequestMapping("/query")
    public Object query(@RequestBody ResDto dto){
        if(dto.getId() != null){
            Res res = this.resService.findObjById(dto.getId());
            if(res != null){
                Map params = new HashMap();
                params.put("parentId", res.getId());
                List<Res> resList = this.resService.findPermissionByMap(params);
                return ResponseUtil.ok(resList);
            }
        }
        return ResponseUtil.badArgument();
    }

    public Object verify(ResDto dto){
        String name = dto.getName();
        if(name == null || name.equals("")){
            return ResponseUtil.badArgument();
        }
        return null;
    }

    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @ApiOperation("权限保存")
    @PostMapping("/save")
    public Object save(@RequestBody ResDto dto){
        if(dto != null){
            Object error = this.verify(dto);
            if(error != null){
                return error;
            }
            if(dto.getParentId() != null && StringUtil.isEmpty(dto.getValue())){
                return ResponseUtil.badArgument("资源信息为空");
            }
            boolean flag = true;
            Map map = new HashMap();
            map.put("name", dto.getName());
            if(dto.getParentId() != null){
//                Res parent = this.resService.findObjById(dto.getParentId());
                map.put("level", 1);
            }else{
                map.put("level", 0);
            }
            Res res = this.resService.findObjByNameAndLevel(map);
            if(res != null) {
                flag = false;
                Res res2 = this.resService.findObjById(dto.getId());
                if(res2 != null){
                    if (res2 != null && !res.getName().equals(res2.getName())) {
                        flag = false;
                    }else{
                        flag = true;
                    }
                }
            }
                if(flag){
                if(dto.getParentId() != null){
                    Res resParent = this.resService.findObjById(dto.getParentId());
                    if(resParent == null){
                        return ResponseUtil.badArgument("填写正确的父级ID");
                    }
                    dto.setLevel(1);
                }
                if(this.resService.save(dto)){
                    return ResponseUtil.ok();
                }
            }
            return ResponseUtil.badArgument("权限已存在");
        }
        return ResponseUtil.badArgument();
    }

    @RequiresPermissions("LK:PERMISSION:MANAGER")
    @ApiOperation("权限删除")
    @PostMapping("/delete")
    public Object delete(@RequestBody ResDto dto){
        // 递归删除
        Res res = this.resService.findObjById(dto.getId());
        if(res != null){
            Map params = new HashMap();
            params.put("parentId", res.getId());
            List<Res> resList = this.resService.findPermissionByMap(params);
            if(resList.size() > 0){
                // ** 可优化为批量删除，首先获取所有子集IdList
                for(Res obj : resList){
                    params.clear();
                    params.put("parentId", obj.getId());
                    if(resList.size() > 0){
                        for(Res obj1 : resList){
                            this.resService.delete(obj1.getId());
                        }
                    }
                    this.resService.delete(obj.getId());
                }
            }
            if(this.resService.delete(res.getId())){
                return ResponseUtil.ok();
            }
            return ResponseUtil.error();
        }
        return ResponseUtil.badArgument();
    }

}
