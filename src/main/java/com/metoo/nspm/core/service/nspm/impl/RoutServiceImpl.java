package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.zabbix.ZabbixRouteMapper;
import com.metoo.nspm.core.service.nspm.IRoutService;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class RoutServiceImpl implements IRoutService {

    @Autowired
    private ZabbixRouteMapper zabbixRoutMapper;

    @Override
    public Route selectObjById(Long id) {
        return this.zabbixRoutMapper.selectObjById(id);
    }

    @Override
    public Page<Route> selectConditionQuery(RoutDTO instance) {
        if(instance == null){
            instance = new RoutDTO();
        }
        Page<Route> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.zabbixRoutMapper.selectConditionQuery(instance);
        return page;
    }

    @Override
    public List<Route> selectObjByMap(Map params) {
        return this.zabbixRoutMapper.selectObjByMap(params);
    }

    @Override
    public int save(Route instance) {
        try {
            if(instance.getId() == null){
                instance.setAddTime(new Date());
            }
            return this.zabbixRoutMapper.save(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public int update(Route instance) {
        try {
            return this.zabbixRoutMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public int delete(Long id) {
        try {
            return this.zabbixRoutMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public void truncateTable() {
        this.zabbixRoutMapper.truncateTable();
    }

    @Override
    public List<Route> queryDestDevice(Map params) {
        return this.zabbixRoutMapper.queryDestDevice(params);
    }

    @Override
    public Route selectDestDevice(Map params) {
        return this.zabbixRoutMapper.selectDestDevice(params);
    }

    @Override
    public List<Route> selectNextHopDevice(Map params) {
        return this.zabbixRoutMapper.selectNextHopDevice(params);
    }

    @Override
    public void copyRoutTemp() {
        this.zabbixRoutMapper.copyRoutTemp();
    }


}
