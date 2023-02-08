package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Home;

import java.util.List;
import java.util.Map;

public interface IHomeService {

    List<Home> selectObjByMap(Map map);

    int save(Home instance);

    int update(Home instance);

    int delete(Long id);
}
