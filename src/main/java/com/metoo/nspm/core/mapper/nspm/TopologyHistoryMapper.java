package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Topology;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface TopologyHistoryMapper {

    int save(Topology instance);

    List<Topology> selectObjByMap(Map params);
}
