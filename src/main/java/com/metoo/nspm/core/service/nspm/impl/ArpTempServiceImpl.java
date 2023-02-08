package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.ArpTempMapper;
import com.metoo.nspm.core.service.nspm.IArpTempService;
import com.metoo.nspm.entity.nspm.ArpTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ArpTempServiceImpl implements IArpTempService {

    @Autowired
    private ArpTempMapper arpTempMapper;

    @Override
    public List<ArpTemp> selectObjByDistinct() {
        return this.arpTempMapper.selectObjByDistinct();
    }

    @Override
    public List<ArpTemp> selectOppositeByMap(Map params) {
        return this.arpTempMapper.selectOppositeByMap(params);
    }

    @Override
    public List<ArpTemp> selectDistinctObjByMap(Map params) {
        return this.arpTempMapper.selectDistinctObjByMap(params);
    }

    @Override
    public List<ArpTemp> selectObjByInterface(Map params) {
        return this.arpTempMapper.selectObjByInterface(params);
    }

    @Override
    public List<ArpTemp> selectObjByMac(Map params) {
        return this.arpTempMapper.selectObjByMac(params);
    }

    @Override
    public List<ArpTemp> selectES(Map params) {
        return this.arpTempMapper.selectES(params);
    }

    @Override
    public List<ArpTemp> selectEAndRemote(Map params) {
        return this.arpTempMapper.selectEAndRemote(params);
    }

    @Override
    public List<ArpTemp> selectObjByGroupMap(Map params) {
        return this.arpTempMapper.selectObjByMap(params);
    }

    @Override
    public List<ArpTemp> selectObjByGroupHavingInterfaceName(Map params) {
        return this.arpTempMapper.selectObjByGroupHavingInterfaceName(params);
    }

    @Override
    public List<ArpTemp> selectObjByMap(Map params) {
        return this.arpTempMapper.selectObjByMap(params);
    }

    @Override
    public List<ArpTemp> arpTag(Map params) {
        return this.arpTempMapper.arpTag(params);
    }

    @Override
    public List<ArpTemp> selectSubquery(Map params) {
        return this.arpTempMapper.selectSubquery(params);
    }

    @Override
    public List<ArpTemp> selectGroupByHavingMac(Map params) {
        return this.arpTempMapper.selectGroupByHavingMac(params);
    }


    @Override
    public ArpTemp selectObjByIp(String ip) {
        return this.arpTempMapper.selectObjByIp(ip);
    }

    @Override
    public int save(ArpTemp instance) {
        if(instance.getId() == null){
            return this.arpTempMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(ArpTemp instance) {
        return this.arpTempMapper.update(instance);
    }

    @Override
    public void truncateTable() {
        this.arpTempMapper.truncateTable();
    }

}
