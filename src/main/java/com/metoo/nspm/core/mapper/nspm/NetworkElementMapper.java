package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.entity.nspm.NetworkElement;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface NetworkElementMapper {

    NetworkElement selectObjById(Long id);

    NetworkElement selectObjByUuid(String uuid);

    List<NetworkElement> selectConditionQuery(NetworkElementDto instance);

    List<NetworkElement> selectObjByMap(Map params);

    List<NetworkElement> selectObjAll();

    int save(NetworkElement instance);

    int batchInsert(List<NetworkElement> instance);

    int update(NetworkElement instance);

    int del(Long id);
}
