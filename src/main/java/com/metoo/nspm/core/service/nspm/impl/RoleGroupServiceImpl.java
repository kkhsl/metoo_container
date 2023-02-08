package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.RoleGroupMapper;
import com.metoo.nspm.core.service.nspm.IRoleGroupService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.dto.RoleGroupDto;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.RoleGroup;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class RoleGroupServiceImpl implements IRoleGroupService {

    @Autowired
    private RoleGroupMapper roleGroupMapper;
    @Autowired
    private IRoleService roleService;

    @Override
    public RoleGroup getObjById(Long id) {
        return this.roleGroupMapper.selectByPrimaryKey(id);
    }

    @Override
    public boolean checkExist(String name) {
        return this.roleGroupMapper.selectObjByNameCount(name) != 0;
    }

    @Override
    public Page<RoleGroup> query(Map<String, Integer> params) {
        Page<RoleGroup> page = PageHelper.startPage(params.get("currentPage"), params.get("pageSize"));

        this.roleGroupMapper.query();
        return page;
    }

    @Override
    public RoleGroup change(Long id) {
        return this.roleGroupMapper.change(id);
    }

    @Override
    public boolean save(RoleGroupDto instance) {
        RoleGroup obj = null;
        if (instance.getId() == null) {
            obj = new RoleGroup();

        } else {
            RoleGroup roleGroup = this.roleGroupMapper.selectByPrimaryKey(instance.getId());
            if (roleGroup != null) {
                obj = roleGroup;
            }
        }
     /*   Accessory accessory = this.accessoryService.getObjById(instance.getIcon());
        if(accessory != null){
            obj.setIcon(accessory);
        }*/
        Map params = new HashMap();
        List<Role> roles = new ArrayList<>();
        // 根据角色的角色组信息
        if (instance.getRole_id() != null && instance.getRole_id().length > 0) {
            List<Integer> idList = Arrays.asList(instance.getRole_id());
            roles = this.roleService.findRoleByIdList(idList);
            //1 清空角色组
            List<Role> roleList = roleService.findRoleByRoleGroupId(obj.getId());
            if (roleList.size() > 0) {
                params.clear();
                params.put("roles", roleList);
                params.put("rg_id", null);
                roleService.batchUpdateRoleGroupId(params);
            }
        }

            if (obj != null) {
                BeanUtils.copyProperties(instance, obj);
                obj.setAddTime(new Date());
                obj.setType("ADMIN");
                if (obj.getId() == null) {
                    try {
                        this.roleGroupMapper.insert(obj);
                        if(roles.size() > 0){
                            params.clear();
                            params.put("roles", roles);
                            params.put("rg_id", obj.getId());
                            roleService.batchUpdateRoleGroupId(params);
                        }
                        return true;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return false;
                    }
                } else {
                    try {
                        this.roleGroupMapper.update(obj);
                        if(roles.size() > 0){
                            params.clear();
                            params.put("roles", roles);
                            params.put("rg_id", obj.getId());
                            roleService.batchUpdateRoleGroupId(params);
                        }
                        return true;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return false;
                    }

                }
            }
        return false;
    }

    @Override
    public Object update(RoleGroup instance) {
        Map map = new HashMap();
        if(instance != null){
            map.put("obj", instance);
            List<Role> groupRoleList = this.roleService.findRoleByRoleGroupId(instance.getId());
            map.put("groupRoleList", groupRoleList);
        }
        List<Role> roles = this.roleService.findRoleByType("ADMIN");
        map.put("roles", roles);
        return map;
    }

    @Override
    public int delete(Long id) {
        try {
            return this.roleGroupMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }

    }

    @Override
    public List<RoleGroup> roleUnitGroup(Map<String, Integer> params) {
        Page<RoleGroup> page = PageHelper.startPage(params.get("currentPage"), params.get("pageSize"));
        this.roleGroupMapper.roleUnitGroup();
        return page;
    }

    @Override
    public List<RoleGroup> selectByPrimaryType(String type) {
        return this.roleGroupMapper.selectByPrimaryType(type);
    }
}
