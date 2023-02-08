package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Grade;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface GradeMapper {

    Grade selectByPrimaryKey(Long id);

    List<Grade> selectByPage(Map<String, Object> paramMap);

    int insert(Grade instance);

    int update(Grade instance);

    int deleteByPrimaryKey(Long id);

    List<Grade> selectAll();

    Grade selectByGradeUnit(Long id);

    List<Grade> query();


    List<Grade> findBycondition(Map params);

    List<Grade> webGradeList();
}
