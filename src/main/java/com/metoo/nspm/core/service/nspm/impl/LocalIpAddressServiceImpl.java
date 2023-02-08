package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.LocalIpAddressMapper;
import com.metoo.nspm.core.service.nspm.ILocalIpAddressService;
import com.metoo.nspm.entity.nspm.LocalIpAddress;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class LocalIpAddressServiceImpl implements ILocalIpAddressService {

    @Autowired
    private LocalIpAddressMapper localIpAddressMapper;

    @Override
    public List<LocalIpAddress> selectObjByMap(Map map) {
        return this.localIpAddressMapper.selectObjByMap(map);
    }

    @Override
    public int save(LocalIpAddress instance) {
        return this.localIpAddressMapper.save(instance);
    }

    @Override
    public void truncateTable() {
        this.localIpAddressMapper.truncateTable();
    }
}
