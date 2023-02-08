package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.DeviceConfigDTO;
import com.metoo.nspm.entity.nspm.DeviceConfig;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface DeviceConfigMapper {

    DeviceConfig selectObjById(Long id);

    List<DeviceConfig> selectConditionQuery(DeviceConfigDTO dto);

    List<DeviceConfig> selectObjByMap(Map params);

    int save(DeviceConfig instance);

    int update(DeviceConfig instance);

    int delete(Long id);

}
