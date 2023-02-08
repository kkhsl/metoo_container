package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.dto.MonitorDto;
import com.metoo.nspm.entity.nspm.Monitor;
import com.github.pagehelper.Page;

public interface IMonitorService {

    Monitor getObjById(Long id);

    Monitor getObjBySign(String sign);

    Page<Monitor> query(MonitorDto dto);

    boolean save(MonitorDto instance);

    boolean update(MonitorDto instance);

    int delete(Long id);
}
