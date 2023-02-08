package com.metoo.nspm.core.mapper.nspm;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface PolicyStatisticalMapper {

    Double getObjByCode(String code);
}
