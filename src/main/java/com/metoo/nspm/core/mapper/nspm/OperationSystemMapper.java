package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.OperationSystem;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface OperationSystemMapper {

    OperationSystem getObjById(Long id);

    List<OperationSystem> selectByMap(Map map);
}
