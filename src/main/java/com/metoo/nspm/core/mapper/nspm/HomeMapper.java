package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Home;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface HomeMapper {

    List<Home> selectObjByMap(Map map);

    int save(Home instance);

    int update(Home instance);

    int delete(Long id);
}
