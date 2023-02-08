package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.DeviceTypeMapper;
import com.metoo.nspm.core.service.nspm.IDeviceTypeService;
import com.metoo.nspm.entity.nspm.DeviceType;
import com.metoo.nspm.vo.DeviceTypeVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;


@Service
@Transactional
public class DeviceTypeServiceImpl implements IDeviceTypeService {

    @Autowired
    private DeviceTypeMapper deviceTypeMapper;

    @Override
    public DeviceType selectObjById(Long id) {
        return this.deviceTypeMapper.selectObjById(id);
    }

    @Override
    public DeviceType selectObjByName(String name) {
        return this.deviceTypeMapper.selectObjByName(name);
    }

    @Override
    public List<DeviceType> selectConditionQuery() {
        return this.deviceTypeMapper.selectConditionQuery();
    }

    @Override
    public List<DeviceType> selectObjByMap(Map params) {
        return this.deviceTypeMapper.selectObjByMap(params);
    }

    @Override
    public List<DeviceType> selectCountByLeftJoin() {
        return this.deviceTypeMapper.selectCountByLeftJoin();
    }

    @Override
    public List<DeviceType> selectCountByJoin() {
        return this.deviceTypeMapper.selectCountByJoin();
    }

    @Override
    public List<DeviceType> selectDeviceTypeAndNeByJoin() {
        return this.deviceTypeMapper.selectDeviceTypeAndNeByJoin();
    }

    @Override
    public List<DeviceTypeVO> statistics() {
        return this.deviceTypeMapper.statistics();
    }
}
