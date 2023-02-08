package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.entity.nspm.Group;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface GroupMapper {

    List<Group> query(Map map);

    Group selectObjById(Long id);

    Group selectObjByName(String name);

    Group getObjByLevel(String level);

    List<Group> selectObjByMap(Map params);

    List<Group> queryChild(Long id);

    boolean save(Group instance);

    boolean update(Group instance);

    boolean del(Long id);

    Group getMaxBranch(String level);
}
