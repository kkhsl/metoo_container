package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.IpAddressTempMapper;
import com.metoo.nspm.core.service.nspm.IIPAddressTempService;
import com.metoo.nspm.entity.nspm.IpAddressTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class IpAddressTempServiceImpl implements IIPAddressTempService {

    @Autowired
    private IpAddressTempMapper ipAddressTempMapper;

    @Override
    public List<IpAddressTemp> selectObjByMap(Map map) {
        return this.ipAddressTempMapper.selectObjByMap(map);
    }

    @Override
    public IpAddressTemp selectObjByMac(String mac) {
        return this.ipAddressTempMapper.selectObjByMac(mac);
    }

    @Override
    public IpAddressTemp selectObjByIp(String ip) {
        return this.ipAddressTempMapper.selectObjByIp(ip);
    }

    @Override
    public int save(IpAddressTemp instance) {
        if(instance.getId() == null){
            return this.ipAddressTempMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(IpAddressTemp instance) {
        return this.ipAddressTempMapper.update(instance);
    }

    @Override
    public void truncateTable() {
        this.ipAddressTempMapper.truncateTable();
    }

    @Override
    public IpAddressTemp querySrcDevice(Map params) {
        return this.ipAddressTempMapper.querySrcDevice(params);
    }
}
