package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.MacHistoryMapper;
import com.metoo.nspm.core.service.nspm.IMacHistoryService;
import com.metoo.nspm.entity.nspm.Mac;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class MacHistoryServiceImpl implements IMacHistoryService {

    @Autowired
    private MacHistoryMapper macHistoryMapper;

    @Override
    public List<Mac> selectObjByMap(Map map) {
        return this.macHistoryMapper.selectObjByMap(map);
    }

    @Override
    public int batchDelete(List<Mac> macs) {
        return this.macHistoryMapper.batchDelete(macs);
    }

    @Override
    public void copyMacTemp() {
        this.macHistoryMapper.copyMacTemp();
    }

}
