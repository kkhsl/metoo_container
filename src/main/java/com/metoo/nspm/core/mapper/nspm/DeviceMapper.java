package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Device;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface DeviceMapper {

    Device selectObjById(Long id);
    List<Device> selectConditionQuery();
}
