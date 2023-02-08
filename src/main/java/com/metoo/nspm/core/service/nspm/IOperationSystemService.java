package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.OperationSystem;

import java.util.List;
import java.util.Map;

public interface IOperationSystemService {

    OperationSystem getObjById(Long id);

    List<OperationSystem> selectByMap(Map map);
}
