package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.zabbix.RouteHistoryMapper;
import com.metoo.nspm.core.service.nspm.IRoutHistoryService;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class RoutHistoryServiceImpl implements IRoutHistoryService {

    @Autowired
    private RouteHistoryMapper routHistoryMapper;

    @Override
    public Route selectObjById(Long id) {
        return this.routHistoryMapper.selectObjById(id);
    }

    @Override
    public Page<Route> selectConditionQuery(RoutDTO instance) {
        if(instance == null){
            instance = new RoutDTO();
        }
        Page<Route> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.routHistoryMapper.selectConditionQuery(instance);
        return page;
    }

    @Override
    public Route selectDestDevice(Map params) {
        return this.routHistoryMapper.selectDestDevice(params);
    }

    @Override
    public int batchDelete(List<Route> routs) {
        return this.routHistoryMapper.batchDelete(routs);
    }

    @Override
    public List<Route> selectObjByMap(Map params) {
        return this.routHistoryMapper.selectObjByMap(params);
    }

    @Override
    public void copyRoutTemp() {
        this.routHistoryMapper.copyRoutTemp();
    }


}
