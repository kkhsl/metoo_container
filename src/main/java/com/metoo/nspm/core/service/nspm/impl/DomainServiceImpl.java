package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.DomainMapper;
import com.metoo.nspm.core.mapper.nspm.GroupMapper;
import com.metoo.nspm.core.service.nspm.IDomainService;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.dto.DomainDTO;
import com.metoo.nspm.entity.nspm.Domain;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class DomainServiceImpl implements IDomainService {

    @Autowired
    private DomainMapper domainMapper;
    @Autowired
    private GroupMapper groupMapper;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;

    @Override
    public Domain selectObjById(Long id) {
        Domain domain = this.domainMapper.selectObjById(id);
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
        return domain;
    }

    @Override
    public Page<Domain> selectObjConditionQuery(DomainDTO dto) {
        Page<Domain> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.domainMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Domain> selectObjByMap(Map params) {
        User user = ShiroUserHolder.currentUser();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
        }
        return this.domainMapper.selectObjByMap(params);
    }

    @Override
    public List<Domain> selectDomainAndVlanByMap(Map params) {
        return this.domainMapper.selectDomainAndVlanByMap(params);
    }

    @Override
    public List<Domain> selectDomainAndVlanProceDureByMap(Map params) {
        return this.domainMapper.selectDomainAndVlanProceDureByMap(params);
    }

    @Override
    public int save(Domain instance) {
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
            instance.setEditDate(new Date());
            User user = ShiroUserHolder.currentUser();
            instance.setGroupId(user.getGroupId());
        }
        if(instance.getId() == null || instance.getId().equals("")){
            try {
                return this.domainMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                instance.setEditDate(new Date());
                return this.domainMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int update(Domain instance) {
        try {
            return this.domainMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.domainMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
