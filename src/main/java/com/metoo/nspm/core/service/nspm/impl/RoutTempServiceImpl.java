package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.RouteTempMapper;
import com.metoo.nspm.core.service.nspm.IRoutTempService;
import com.metoo.nspm.entity.nspm.RouteTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class RoutTempServiceImpl implements IRoutTempService {

    @Autowired
    private RouteTempMapper routTempMapper;

    @Override
    public RouteTemp selectObjById(Long id) {
        return this.routTempMapper.selectObjById(id);
    }

    @Override
    public List<RouteTemp> selectObjByMap(Map params) {
        return this.routTempMapper.selectObjByMap(params);
    }

    @Override
    public int save(RouteTemp instance) {
        try {
            if(instance.getId() == null){
                if(instance.getAddTime() == null){
                    instance.setAddTime(new Date());
                }
            }
            return this.routTempMapper.save(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public int update(RouteTemp instance) {
        try {
            return this.routTempMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public int delete(Long id) {
        try {
            return this.routTempMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public void truncateTable() {
        this.routTempMapper.truncateTable();
    }

    @Override
    public List<RouteTemp> queryDestDevice(Map params) {
        return this.routTempMapper.queryDestDevice(params);
    }

    @Override
    public RouteTemp selectDestDevice(Map params) {
        return this.routTempMapper.selectDestDevice(params);
    }

    @Override
    public List<RouteTemp> selectNextHopDevice(Map params) {
        return this.routTempMapper.selectNextHopDevice(params);
    }


}
