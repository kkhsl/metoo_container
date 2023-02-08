package com.metoo.nspm.core.service.nspm;

import com.metoo.nspm.entity.nspm.Threshold;

public interface IThresholdService {

    Threshold query();

    int update(Threshold instance);
}
