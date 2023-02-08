package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.SysConfig;

public interface ISysConfigService {

    SysConfig findObjById(Long id);

    SysConfig  select();

    int modify(SysConfig instance);

    boolean update(SysConfig instance);
}
