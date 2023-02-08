package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.IpAddressHistoryMapper;
import com.metoo.nspm.core.service.nspm.IIPAddressHistoryService;
import com.metoo.nspm.entity.nspm.IpAddress;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class IpAddressHistoryServiceImpl implements IIPAddressHistoryService {

    @Autowired
    private IpAddressHistoryMapper ipAddressHistoryMapper;

    @Override
    public List<IpAddress> selectObjByMap(Map map) {
        return this.ipAddressHistoryMapper.selectObjByMap(map);
    }

    @Override
    public IpAddress selectObjByMac(String mac) {
        return this.ipAddressHistoryMapper.selectObjByMac(mac);
    }

    @Override
    public IpAddress selectObjByIp(String ip) {
        return this.ipAddressHistoryMapper.selectObjByIp(ip);
    }

    @Override
    public IpAddress querySrcDevice(Map params) {
        return this.ipAddressHistoryMapper.querySrcDevice(params);
    }

    @Override
    public int batchDelete(List<IpAddress> ipAddresses) {
        return this.ipAddressHistoryMapper.batchDelete(ipAddresses);
    }

    @Override
    public void copyIpAddressTemp() {
        this.ipAddressHistoryMapper.copyIpAddressTemp();
    }

}
