package com.metoo.nspm.core.service.nspm;

import com.github.pagehelper.Page;
import com.metoo.nspm.dto.DeviceConfigDTO;
import com.metoo.nspm.entity.nspm.DeviceConfig;

import java.util.List;
import java.util.Map;

public interface IDeviceConfigService {

    DeviceConfig selectObjById(Long id);

    Page<DeviceConfig> selectConditionQuery(DeviceConfigDTO dto);

    List<DeviceConfig> selectObjByMap(Map params);

    int save(DeviceConfig instance);

    int update(DeviceConfig instance);

    int delete(Long id);
}
