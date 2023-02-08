package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.TopologyHistoryMapper;
import com.metoo.nspm.core.service.nspm.ITopologyHistoryService;
import com.metoo.nspm.entity.nspm.Topology;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class TopologyHistoryServiceImpl implements ITopologyHistoryService {

    @Autowired
    private TopologyHistoryMapper topologyHistoryMapper;

    @Override
    public List<Topology> selectObjByMap(Map params) {
        return this.topologyHistoryMapper.selectObjByMap(params);
    }

}
