package com.metoo.nspm.core.mapper.topology;

import com.metoo.nspm.entity.nspm.TopologyToken;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface TopologyTokenMapper {

    List<TopologyToken> query(Map map);
}
