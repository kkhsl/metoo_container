package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.RoleRes;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface RoleResMapper {

    int insert(List<RoleRes> roleResList);

    int delete(Long id);
}
