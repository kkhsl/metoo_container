package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Threshold;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ThresholdMapper {

    Threshold query();

    int update(Threshold instance);
}
