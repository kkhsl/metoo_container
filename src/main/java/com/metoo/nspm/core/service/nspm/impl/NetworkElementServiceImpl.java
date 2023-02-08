package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.NetworkElementMapper;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.INetworkElementService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.NetworkElement;
import com.metoo.nspm.entity.nspm.User;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class NetworkElementServiceImpl implements INetworkElementService {

    @Autowired
    private NetworkElementMapper networkElementMapper;
    @Autowired
    private IGroupService groupService;

    @Override
    public NetworkElement selectObjById(Long id) {
        return this.networkElementMapper.selectObjById(id);
    }

    @Override
    public NetworkElement selectObjByUuid(String uuid) {
        return this.networkElementMapper.selectObjByUuid(uuid);
    }


    @Override
    public Page<NetworkElement> selectConditionQuery(NetworkElementDto instance) {
        if(instance == null){
            instance = new NetworkElementDto();
        }
        Page<NetworkElement> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.networkElementMapper.selectConditionQuery(instance);
        return page;
}

    @Override
    public List<NetworkElement> selectObjByMap(Map params) {

        return this.networkElementMapper.selectObjByMap(params);
    }

    @Override
    public List<NetworkElement> selectObjAll() {
        return this.networkElementMapper.selectObjAll();
    }

    @Override
    public int save(NetworkElement instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            instance.setUuid(UUID.randomUUID().toString());
            User user = ShiroUserHolder.currentUser();
            instance.setUserId(user.getId());
            instance.setUserName(user.getUsername());
            try {
                return this.networkElementMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.networkElementMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int batchInsert(List<NetworkElement> instances) {
        for (NetworkElement instance : instances) {
            instance.setAddTime(new Date());
            instance.setUuid(UUID.randomUUID().toString());
            User user = ShiroUserHolder.currentUser();
            instance.setUserId(user.getId());
            instance.setUserName(user.getUsername());
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null){
                instance.setGroupId(group.getId());
                instance.setGroupName(group.getBranchName());
            }
        }
        try {
            int i = this.networkElementMapper.batchInsert(instances);
            return i;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int update(NetworkElement instance) {
        try {
            this.networkElementMapper.update(instance);
            return 1;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int del(Long id) {
        try {
            this.networkElementMapper.del(id);
            return 1;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
