package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.VirtualServerDto;
import com.metoo.nspm.entity.nspm.VirtualServer;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface VirtualServerMapper {

    VirtualServer getObjById(Long id);

    List<VirtualServer> selectList(VirtualServerDto instance);

    int insert(VirtualServer instance);

    int update(VirtualServer instance);

    int deleteById(Long id);

    int deleteByMap(Map map);

}
