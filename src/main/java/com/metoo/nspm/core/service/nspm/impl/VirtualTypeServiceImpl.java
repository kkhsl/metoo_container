package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.VirtualTypeMapper;
import com.metoo.nspm.core.service.nspm.IVirtualTypeService;
import com.metoo.nspm.entity.nspm.VirtualType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class VirtualTypeServiceImpl implements IVirtualTypeService {

    @Autowired
    private VirtualTypeMapper virtualTypeMapper;

    @Override
    public VirtualType getObjById(Long id) {
        return this.virtualTypeMapper.getObjById(id);
    }

    @Override
    public List<VirtualType> selectByMap(Map map) {
        return this.virtualTypeMapper.selectByMap(map);
    }
}
