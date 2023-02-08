package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.RouteTableMapper;
import com.metoo.nspm.core.service.nspm.IRoutTableService;
import com.metoo.nspm.entity.nspm.RouteTable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class RoutTableServiceImpl implements IRoutTableService {

    @Autowired
    private RouteTableMapper routTableMapper;

    @Override
    public List<RouteTable> selectObjByMap(Map map) {
        return this.routTableMapper.selectObjByMap(map);
    }

    @Override
    public RouteTable selectObjByMac(String mac) {
        return this.routTableMapper.selectObjByMac(mac);
    }

    @Override
    public RouteTable selectObjByIp(String ip) {
        return this.routTableMapper.selectObjByIp(ip);
    }

    @Override
    public int save(RouteTable instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            try {
                return this.routTableMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                this.routTableMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
        return 0;
    }

    @Override
    public int update(RouteTable instance) {
        return this.routTableMapper.update(instance);
    }

    @Override
    public void truncateTable() {
        this.routTableMapper.truncateTable();
    }
}
