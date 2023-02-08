package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.IpDetailMapper;
import com.metoo.nspm.core.service.nspm.IpDetailService;
import com.metoo.nspm.entity.nspm.IpDetail;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class IpDetailServiceImpl implements IpDetailService {

    @Autowired
    private IpDetailMapper ipDetailMapper;

    @Override
    public List<IpDetail> selectObjByMap(Map map) {
        return this.ipDetailMapper.selectObjByMap(map);
    }

    @Override
    public IpDetail selectObjByMac(String mac) {
        return this.ipDetailMapper.selectObjByMac(mac);
    }

    @Override
    public IpDetail selectObjByIp(String ip) {
        return this.ipDetailMapper.selectObjByIp(ip);
    }

    @Override
    public int save(IpDetail instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            return this.ipDetailMapper.save(instance);
        }else{
            return this.ipDetailMapper.update(instance);
        }
    }

    @Override
    public int update(IpDetail instance) {
        return this.ipDetailMapper.update(instance);
    }
}
