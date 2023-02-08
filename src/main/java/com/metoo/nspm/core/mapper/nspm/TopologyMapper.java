package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.TopologyDTO;
import com.metoo.nspm.entity.nspm.Topology;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface TopologyMapper {

    Topology selectObjById(Long id);

    Topology selectObjBySuffix(String name);

    List<Topology> selectConditionQuery(TopologyDTO instance);

    List<Topology> selectObjByMap(Map params);

    List<Topology> selectTopologyByMap(Map params);

    int save(Topology instance);

    int update(Topology instance);

    int delete(Long id);

    int copy(Topology instance);
}
