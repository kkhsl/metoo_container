package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.SysConfigMapper;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.entity.nspm.SysConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class SysConfigServiceImpl implements ISysConfigService {

    @Autowired
    private SysConfigMapper sysConfigMapper;

    @Override
    public SysConfig findObjById(Long id) {
        return this.sysConfigMapper.findObjById();
    }

    @Override
    public SysConfig select() {
        return this.sysConfigMapper.select();
    }

    @Override
    public int modify(SysConfig instance) {
        instance.setDomain("httpclient://" + instance.getIp());
        return this.sysConfigMapper.update(instance);
    }

    @Override
    public boolean update(SysConfig instance) {
        try {
            this.sysConfigMapper.update(instance);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
