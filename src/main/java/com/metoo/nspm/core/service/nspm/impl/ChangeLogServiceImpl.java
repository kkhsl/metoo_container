package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.ChangeLogMapper;
import com.metoo.nspm.core.service.nspm.IChangeLogService;
import com.metoo.nspm.dto.ChangeLogDto;
import com.metoo.nspm.entity.nspm.ChangeLog;
import com.metoo.nspm.entity.nspm.User;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@Transactional
public class ChangeLogServiceImpl implements IChangeLogService {

    @Autowired
    private ChangeLogMapper changeLogMapper;

    @Override
    public Page<ChangeLog> findBySelect(ChangeLogDto instance) {
        if(instance == null){
            instance = new ChangeLogDto();
        }
        User user = ShiroUserHolder.currentUser();
        instance.setUserId(user.getId());
        Page<ChangeLog> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.changeLogMapper.findBySelect(instance);
        return page;
    }

    @Override
    public int save(ChangeLog instance) {
        instance.setAddTime(new Date());
        User user = ShiroUserHolder.currentUser();
        instance.setUserName(user.getUsername());
        instance.setUserId(user.getId());
        return this.changeLogMapper.save(instance);
    }
}
