package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.PolicyStatisticalMapper;
import com.metoo.nspm.core.service.nspm.IPolicyStatisticalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PolicyStatisticalServiceImpl implements IPolicyStatisticalService {

    @Autowired
    private PolicyStatisticalMapper policyStatisticalMapper;

    @Override
    public Double getObjByCode(String code) {
        return this.policyStatisticalMapper.getObjByCode(code);
    }
}
