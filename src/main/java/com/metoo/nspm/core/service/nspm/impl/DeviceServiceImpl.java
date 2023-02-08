package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.DeviceMapper;
import com.metoo.nspm.core.service.nspm.IDeviceService;
import com.metoo.nspm.entity.nspm.Device;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class DeviceServiceImpl implements IDeviceService {

    @Autowired
    private DeviceMapper deviceMapper;

    @Override
    public Device selectObjById(Long id) {
        return this.deviceMapper.selectObjById(id);
    }

    @Override
    public List<Device> selectConditionQuery() {
        return this.deviceMapper.selectConditionQuery();
    }
}
