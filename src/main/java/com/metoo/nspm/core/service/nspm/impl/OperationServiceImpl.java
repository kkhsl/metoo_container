package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.OperationSystemMapper;
import com.metoo.nspm.core.service.nspm.IOperationSystemService;
import com.metoo.nspm.entity.nspm.OperationSystem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class OperationServiceImpl implements IOperationSystemService {

    @Autowired
    private OperationSystemMapper operationSystemMapper;

    @Override
    public OperationSystem getObjById(Long id) {
        return this.operationSystemMapper.getObjById(id);
    }

    @Override
    public List<OperationSystem> selectByMap(Map map) {
        return this.operationSystemMapper.selectByMap(map);
    }
}
