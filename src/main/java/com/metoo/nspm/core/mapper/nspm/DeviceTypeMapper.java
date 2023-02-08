package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.DeviceType;
import com.metoo.nspm.vo.DeviceTypeVO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface DeviceTypeMapper {

    DeviceType selectObjById(Long id);

    DeviceType selectObjByName(String name);

    List<DeviceType> selectConditionQuery();

    List<DeviceType> selectObjByMap(Map params);

    List<DeviceType> selectCountByLeftJoin();

    List<DeviceType> selectCountByJoin();

    List<DeviceType> selectDeviceTypeAndNeByJoin();

    List<DeviceTypeVO> statistics();

}
