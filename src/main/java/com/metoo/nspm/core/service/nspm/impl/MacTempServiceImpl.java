package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.MacTempMapper;
import com.metoo.nspm.core.service.nspm.IMacTempService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.MacTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class MacTempServiceImpl implements IMacTempService {

    @Autowired
    private MacTempMapper macTempMapper;

    @Override
    public List<MacTemp> selectByMap(Map map) {
        return this.macTempMapper.selectByMap(map);
    }

    @Override
    public MacTemp getObjByInterfaceName(String interfaceName) {
        return this.macTempMapper.getObjByInterfaceName(interfaceName);
    }

    @Override
    public List<MacTemp> groupByObjByMap(Map params) {
        return this.macTempMapper.groupByObjByMap(params);
    }

    @Override
    public List<MacTemp> groupByObjByMap2(Map params) {
        return this.macTempMapper.groupByObjByMap2(params);
    }


    @Override
    public List<MacTemp> getMacUS(Map params) {
        return this.macTempMapper.getMacUS(params);
    }

    @Override
    public List<MacTemp> macJoinArp(Map params) {
        return this.macTempMapper.macJoinArp(params);
    }

    @Override
    public MacTemp selectByMac(String mac) {
        return this.macTempMapper.selectByMac(mac);
    }

    @Override
    public int save(MacTemp instance) {
        if(instance.getId() == null){
            if(instance.getAddTime() == null){
                instance.setAddTime(new Date());
            }
            return this.macTempMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(MacTemp instance) {
        if(instance.getId() != null){
            if(instance.getIp() != null && instance.getIp().contains(".")){
                instance.setIp(IpUtil.ipConvertDec(instance.getIp()));
            }
            return this.macTempMapper.update(instance);
        }
        return 0;
    }

    @Override
    public void truncateTable() {
        this.macTempMapper.truncateTable();
    }
}
