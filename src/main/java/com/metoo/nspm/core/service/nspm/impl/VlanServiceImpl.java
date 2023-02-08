package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.GroupMapper;
import com.metoo.nspm.core.mapper.nspm.VlanMapper;
import com.metoo.nspm.core.service.nspm.IVlanService;
import com.metoo.nspm.dto.VlanDTO;
import com.metoo.nspm.entity.nspm.User;
import com.metoo.nspm.entity.nspm.Vlan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class VlanServiceImpl implements IVlanService {

    @Autowired
    private VlanMapper vlanMapper;
    @Autowired
    private GroupMapper groupMapper;

    @Override
    public Vlan selectObjById(Long id) {
        Vlan vlan = this.vlanMapper.selectObjById(id);
//        if(vlan != null){
//            User user = ShiroUserHolder.currentUser();
//            Long groupId = user.getGroupId();
//            Group group = this.groupMapper.selectObjById(groupId);
//            if(group != null){
//                List<Group> groups = this.groupMapper.queryChild(groupId);
//                Group vlanGroup = this.groupMapper.selectObjById(vlan.getGroupId());
//                if(groups.contains(vlanGroup)){
//                    return vlan;
//                }
//            }
//        }
        return vlan;
    }

    @Override
    public Page<Vlan> selectObjConditionQuery(VlanDTO dto) {
        Page<Vlan> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.vlanMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Vlan> selectObjByMap(Map params) {
        return this.vlanMapper.selectObjByMap(params);
    }

    @Override
    public int save(Vlan instance) {
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
            instance.setEditDate(new Date());
            User user = ShiroUserHolder.currentUser();
            instance.setGroupId(user.getGroupId());
        }

        if(instance.getId() == null || instance.getId().equals("")){
            try {
                return this.vlanMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                instance.setEditDate(new Date());
                return this.vlanMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int update(Vlan instance) {
        try {
            instance.setEditDate(new Date());
            return this.vlanMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.vlanMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
