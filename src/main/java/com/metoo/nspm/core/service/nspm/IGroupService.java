package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.GroupDto;
import com.metoo.nspm.entity.nspm.Group;

import java.util.List;
import java.util.Map;

public interface IGroupService {

    List<Group> query(Map map);

    Group selectObjById(Long id);

    Group selectObjByName(String name);

    Group getObjByLevel(String level);

    List<Group> selectObjByMap(Map params);

    List<Group> queryChild(Long id);

    boolean save(GroupDto instance);

    boolean del(Long id);

}
