package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.IpAddressMapper;
import com.metoo.nspm.core.service.nspm.IIPAddressService;
import com.metoo.nspm.entity.nspm.IpAddress;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class IpAddressServiceImpl implements IIPAddressService {

    @Autowired
    private IpAddressMapper ipAddressMapper;

    @Override
    public List<IpAddress> selectObjByMap(Map map) {
        return this.ipAddressMapper.selectObjByMap(map);
    }

    @Override
    public IpAddress selectObjByMac(String mac) {
        return this.ipAddressMapper.selectObjByMac(mac);
    }

    @Override
    public IpAddress selectObjByIp(String ip) {
        return this.ipAddressMapper.selectObjByIp(ip);
    }

    @Override
    public int save(IpAddress instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            return this.ipAddressMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(IpAddress instance) {
        return this.ipAddressMapper.update(instance);
    }

    @Override
    public void truncateTable() {
        this.ipAddressMapper.truncateTable();
    }

    @Override
    public void copyIpAddressTemp() {
        this.ipAddressMapper.copyIpAddressTemp();
    }

    @Override
    public IpAddress querySrcDevice(Map params) {
        return this.ipAddressMapper.querySrcDevice(params);
    }
}
