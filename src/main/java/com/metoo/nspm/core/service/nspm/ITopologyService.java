package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.TopologyDTO;
import com.metoo.nspm.entity.nspm.Topology;
import com.github.pagehelper.Page;

import java.util.List;
import java.util.Map;

public interface ITopologyService {

    Topology selectObjById(Long id);

    Topology selectObjBySuffix(String name);

    Page<Topology> selectConditionQuery(TopologyDTO instance);

    List<Topology> selectObjByMap(Map params);

    List<Topology> selectTopologyByMap(Map params);

    int save(Topology instance);

    int update(Topology instance);

    int delete(Long id);

    Long copy(Topology instance);
}
