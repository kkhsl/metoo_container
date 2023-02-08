package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.DeviceType;
import com.metoo.nspm.vo.DeviceTypeVO;

import java.util.List;
import java.util.Map;

public interface IDeviceTypeService {

    DeviceType selectObjById(Long id);

    DeviceType selectObjByName(String name);

    List<DeviceType> selectConditionQuery();

    List<DeviceType> selectObjByMap(Map params);

    List<DeviceType> selectCountByLeftJoin();

    List<DeviceType> selectCountByJoin();

    List<DeviceType> selectDeviceTypeAndNeByJoin();

    List<DeviceTypeVO> statistics();
}
