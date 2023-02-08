package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.VirtualType;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface VirtualTypeMapper {

    VirtualType getObjById(Long id);

    List<VirtualType> selectByMap(Map map);
}
