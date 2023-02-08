package com.metoo.nspm.core.service.zabbix.impl;

import com.metoo.nspm.core.mapper.nspm.zabbix.ProblemTempMapper;
import com.metoo.nspm.core.service.zabbix.IProblemTempService;
import com.metoo.nspm.entity.nspm.ProblemTemp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ProblemTempServiceImpl implements IProblemTempService {

    @Autowired
    private ProblemTempMapper problemTempMapper;

    @Override
    public void truncateTable() {
        this.problemTempMapper.truncateTable();
    }

    @Override
    public int batchInsert(List<ProblemTemp> instance) {
        try {
            return this.problemTempMapper.batchInsert(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public ProblemTemp selectObjByObjectId(Integer objectid) {
        return this.problemTempMapper.selectObjByObjectId(objectid);
    }

    @Override
    public List<ProblemTemp> selectObjByMap(Map params) {
        return this.problemTempMapper.selectObjByMap(params);
    }

    @Override
    public int update(ProblemTemp instance) {
        try {
            return this.problemTempMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

}
