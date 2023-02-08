package com.metoo.nspm.core.service.nspm.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.zabbix.ArpMapper;
import com.metoo.nspm.core.service.nspm.IArpService;
import com.metoo.nspm.dto.ArpDTO;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.entity.nspm.Arp;
import com.metoo.nspm.entity.nspm.NetworkElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ArpServiceImpl implements IArpService {

    @Autowired
    private ArpMapper arpMapper;

    @Override
    public List<Arp> selectObjByDistinct() {
        return this.arpMapper.selectObjByDistinct();
    }

    @Override
    public List<Arp> selectOppositeByMap(Map params) {
        return this.arpMapper.selectOppositeByMap(params);
    }

    @Override
    public List<Arp> selectDistinctObjByMap(Map params) {
        return this.arpMapper.selectDistinctObjByMap(params);
    }

    @Override
    public List<Arp> selectObjByInterface(Map params) {
        return this.arpMapper.selectObjByInterface(params);
    }

    @Override
    public List<Arp> selectObjByMac(Map params) {
        return this.arpMapper.selectObjByMac(params);
    }

    @Override
    public List<Arp> selectES(Map params) {
        return this.arpMapper.selectES(params);
    }

    @Override
    public List<Arp> selectEAndRemote(Map params) {
        return this.arpMapper.selectEAndRemote(params);
    }

    @Override
    public List<Arp> selectObjByGroupMap(Map params) {
        return this.arpMapper.selectObjByMap(params);
    }

    @Override
    public List<Arp> selectObjByGroupHavingInterfaceName(Map params) {
        return this.arpMapper.selectObjByGroupHavingInterfaceName(params);
    }

    @Override
    public Page<Arp> selectObjConditionQuery(ArpDTO dto) {
        if(dto == null){
            dto = new ArpDTO();
        }
        Page<Arp> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.arpMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Arp> selectObjByMap(Map params) {
        return this.arpMapper.selectObjByMap(params);
    }

    @Override
    public List<Arp> arpTag(Map params) {
        return this.arpMapper.arpTag(params);
    }

    @Override
    public List<Arp> selectSubquery(Map params) {
        return this.arpMapper.selectSubquery(params);
    }

    @Override
    public List<Arp> selectGroupByHavingMac(Map params) {
        return this.arpMapper.selectGroupByHavingMac(params);
    }


    @Override
    public Arp selectObjByIp(String ip) {
        return this.arpMapper.selectObjByIp(ip);
    }

    @Override
    public int save(Arp instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
            return this.arpMapper.save(instance);
        }
        return 0;
    }

    @Override
    public int update(Arp instance) {
        return this.arpMapper.update(instance);
    }

    @Override
    public void truncateTable() {
        this.arpMapper.truncateTable();
    }

    @Override
    public void copyArpTemp(){
        this.arpMapper.copyArpTemp();
    }

    @Override
    public List<Arp> selectObjByMutual() {
        return this.arpMapper.selectObjByMutual();
    }
}
