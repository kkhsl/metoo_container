package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Performance;
import org.apache.ibatis.annotations.Mapper;

import java.util.Map;

@Mapper
public interface PerformenceMapper {

    Performance getObjBy(Map params);
}
