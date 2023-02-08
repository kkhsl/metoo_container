package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.ZabbixSubnetMapper;
import com.metoo.nspm.core.service.nspm.ZabbixSubnetService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.Subnet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class SubnetServiceImpl implements ZabbixSubnetService {

    @Autowired
    private ZabbixSubnetMapper zabbixSubnetMapper;

    @Override
    public Subnet selectObjById(Long id) {
        return this.zabbixSubnetMapper.selectObjById(id);
    }

    @Override
    public Subnet selectObjByIp(String ip, Integer mask) {
        return this.zabbixSubnetMapper.selectObjByIp(IpUtil.ipConvertDec(ip), mask);
    }

    @Override
    public List<Subnet> selectSubnetByParentId(Long id) {
        return this.zabbixSubnetMapper.selectSubnetByParentId(id);
    }

    @Override
    public List<Subnet> selectSubnetByParentIp(Long ip) {
        return this.zabbixSubnetMapper.selectSubnetByParentIp(ip);
    }

    @Override
    public int save(Subnet subnet) {
        try {
            subnet.setAddTime(new Date());
            return this.zabbixSubnetMapper.save(subnet);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int update(Subnet subnet) {
        try {
            return this.zabbixSubnetMapper.update(subnet);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.zabbixSubnetMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }
}
