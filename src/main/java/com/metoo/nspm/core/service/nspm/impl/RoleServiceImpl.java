package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.RoleMapper;
import com.metoo.nspm.core.service.nspm.IResService;
import com.metoo.nspm.core.service.nspm.IRoleResService;
import com.metoo.nspm.core.service.nspm.IRoleService;
import com.metoo.nspm.dto.RoleDto;
import com.metoo.nspm.entity.nspm.Res;
import com.metoo.nspm.entity.nspm.Role;
import com.metoo.nspm.entity.nspm.RoleRes;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;


@Service
@Transactional
public class RoleServiceImpl implements IRoleService {

    @Autowired
    private RoleMapper roleMapper;
    @Autowired
    private IResService resService;
    @Autowired
    private IRoleResService roleResService;

    @Override
    public Role findRoleById(Long id) {
        return this.roleMapper.findRoleById(id);
    }

    @Override
    public Role findObjByName(String name) {
        return this.roleMapper.findRoleByName(name);
    }


    @Override
    public List<Role> findRoleByType(String type) {
        return this.roleMapper.findRoleByType(type);
    }

    @Override
    public List<Role> findRoleByUserId(Long user_id) {
        return this.roleMapper.findRoleByUserId(user_id);
    }

    @Override
    public List<Role> findRoleByRoleGroupId(Long role_group_id) {
        return this.roleMapper.findRoleByRoleGroupId(role_group_id);
    }

    @Override
    public List<Role> findRoleByResId(Long res_id) {
        return this.roleMapper.findRoleByResId(res_id);
    }

    @Override
    public List<Role> findRoleByIdList(List<Integer> list) {
        return this.roleMapper.findRoleByIdList(list);
    }

    @Override
    public Role selectByPrimaryUpdae(Long id) {
        return this.roleMapper.selectByPrimaryUpdae(id);
    }

    @Override
    public boolean save(RoleDto instance) {
        Role role = null;
        if(instance.getId() == null){
            role = new Role();
            role.setAddTime(new Date());
        }else{
            role = this.roleMapper.findRoleById(instance.getId());
        }
        BeanUtils.copyProperties(instance, role);
        if(role.getId() == null){
            try {
                this.roleMapper.insert(role);
                // 批量添加权限
                if(instance.getRes_id() != null && instance.getRes_id().length > 0){
                    List<Integer> idList = Arrays.asList(instance.getRes_id());
                    List<Res> resList = this.resService.findResByResIds(idList);
                    List<RoleRes> roleResList = new ArrayList<RoleRes>();
                    for(Res res : resList){
                        RoleRes roleRes = new RoleRes();
                        roleRes.setRes_id(res.getId());
                        roleRes.setRole_id(role.getId());
                        roleResList.add(roleRes);
                    }
                    this.roleResService.batchAddRoleRes(roleResList);
                }
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                if(instance.getRes_id() != null){
                    // 清除角色权限信息
                    this.roleResService.deleteRoleResByRoleId(role.getId());
                    // 批量添加权限
                    List<Integer> idList = Arrays.asList(instance.getRes_id());
                    if(idList.size() > 0){
                        List<Res> resList = this.resService.findResByResIds(idList);
                        List<RoleRes> roleResList = new ArrayList<RoleRes>();
                        for(Res res : resList){
                            RoleRes roleRes = new RoleRes();
                            roleRes.setRes_id(res.getId());
                            roleRes.setRole_id(role.getId());
                            roleResList.add(roleRes);
                        }
                        this.roleResService.batchAddRoleRes(roleResList);
                    }
                }
                this.roleMapper.update(role);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public Object update(RoleDto instance) {
        return null;
    }

    @Override
    public Page<Role> query(RoleDto dto) {
        Page<Role> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
            this.roleMapper.query(dto);
        return page;
    }

    @Override
    public List<Role> findObjByMap(Map params) {

        Page<Role> page = PageHelper.startPage((Integer)params.get("currentPage"), (Integer)params.get("pageSize"));

        return this.roleMapper.findObjByMap(params);

    }

    @Override
    public boolean delete(Long id) {
        int flag = this.roleMapper.delete(id);
        return flag != 0;
    }

    @Override
    public int batchUpdateRoleGroupId(Map map) {
        return this.roleMapper.batchUpdateRoleGroupId(map);

    }

}
