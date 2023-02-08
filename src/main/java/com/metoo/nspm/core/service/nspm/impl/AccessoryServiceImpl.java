package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.AccessoryMapper;
import com.metoo.nspm.core.service.nspm.IAccessoryService;
import com.metoo.nspm.entity.nspm.Accessory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class AccessoryServiceImpl implements IAccessoryService {

    @Autowired
    private AccessoryMapper accessoryMapper;

    @Override
    public Accessory getObjById(Long id) {
        return this.accessoryMapper.getObjById(id);
    }

    @Override
    public int save(Accessory instance) {
        return this.accessoryMapper.save(instance);
    }

    @Override
    public int update(Accessory instance) {
        return this.accessoryMapper.update(instance);
    }

    @Override
    public int delete(Long id) {
        return this.accessoryMapper.delete(id);
    }

    @Override
    public List<Accessory> query(Map params) {
        return this.accessoryMapper.query(params);
    }
}
