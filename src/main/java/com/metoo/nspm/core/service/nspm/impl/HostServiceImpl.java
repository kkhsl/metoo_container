package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.HostMapper;
import com.metoo.nspm.core.service.nspm.IHostService;
import com.metoo.nspm.dto.HostDTO;
import com.metoo.nspm.entity.nspm.Host;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class HostServiceImpl implements IHostService {

    @Autowired
    private HostMapper hostMapper;

    @Override
    public Host selectObjById(Long id) {
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        params.put("id", id);
        params.put("userId", user.getId());
        List<Host> hosts = this.hostMapper.selectObjByMap(params);
        if(hosts.size() > 0){
            return hosts.get(0);
        }
        return null;
    }

    @Override
    public Page<Host> selectConditionQuery(HostDTO instance) {
        if(instance == null){
            instance = new HostDTO();
        }
        Page<Host> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.hostMapper.selectConditionQuery(instance);
        return page;
    }

    @Override
    public List<Host> selectObjByMap(Map params) {
        return this.hostMapper.selectObjByMap(params);
    }

    @Override
    public int save(Host instance) {
        if(instance.getId() == null){
            try {
                User user = ShiroUserHolder.currentUser();
                instance.setAddTime(new Date());
                instance.setUuid(UUID.randomUUID().toString());
                instance.setUserId(user.getId());
                instance.setUserName(user.getUsername());
                return this.hostMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.hostMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int update(Host instance) {
        try {
            return this.hostMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        return this.hostMapper.delete(id);
    }
}
