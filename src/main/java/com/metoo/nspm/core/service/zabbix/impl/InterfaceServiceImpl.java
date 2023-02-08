package com.metoo.nspm.core.service.zabbix.impl;

import com.metoo.nspm.core.mapper.zabbix.InterfaceMapper;
import com.metoo.nspm.core.service.zabbix.InterfaceService;
import com.metoo.nspm.entity.zabbix.Interface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class InterfaceServiceImpl implements InterfaceService {

    @Autowired
    private InterfaceMapper interfaceMapper;

    @Override
    public Interface selectObjByIp(String ip) {
        return this.interfaceMapper.selectObjByIp(ip);
    }
}
