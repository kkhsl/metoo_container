package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.zabbix.MacMapper;
import com.metoo.nspm.core.service.nspm.IMacService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.dto.ArpDTO;
import com.metoo.nspm.dto.MacDTO;
import com.metoo.nspm.entity.nspm.Arp;
import com.metoo.nspm.entity.nspm.Mac;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class MacServiceImpl implements IMacService{

    @Autowired
    private MacMapper macMapper;

    @Override
    public Page<Mac> selectObjConditionQuery(MacDTO dto) {
        if(dto == null){
            dto = new MacDTO();
        }
        Page<Mac> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.macMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Mac> selectByMap(Map map) {
        return this.macMapper.selectByMap(map);
    }

    @Override
    public Mac getObjByInterfaceName(String interfaceName) {
        return this.macMapper.getObjByInterfaceName(interfaceName);
    }

    @Override
    public List<Mac> groupByObjByMap(Map params) {
        return this.macMapper.groupByObjByMap(params);
    }

    @Override
    public List<Mac> groupByObjByMap2(Map params) {
        return this.macMapper.groupByObjByMap2(params);
    }


    @Override
    public List<Mac> getMacUS(Map params) {
        return this.macMapper.getMacUS(params);
    }

    @Override
    public List<Mac> macJoinArp(Map params) {
        return this.macMapper.macJoinArp(params);
    }

    @Override
    public Mac selectByMac(String mac) {
        return this.macMapper.selectByMac(mac);
    }

    @Override
    public int save(Mac instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            return this.macMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(Mac instance) {
        if(instance.getId() != null){
            if(instance.getIp() != null && instance.getIp().contains(".")){
                instance.setIp(IpUtil.ipConvertDec(instance.getIp()));
            }
            return this.macMapper.update(instance);
        }
        return 0;
    }

    @Override
    public void truncateTable() {
        this.macMapper.truncateTable();
    }

    @Override
    public void copyMacTemp() {
        this.macMapper.copyMacTemp();
    }

}
