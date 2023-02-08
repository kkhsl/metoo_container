package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Invisible;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface InvisibleMapper {

    // 查询所有未使用字符
    List<Invisible> query();

    int update(Invisible instance);
}
