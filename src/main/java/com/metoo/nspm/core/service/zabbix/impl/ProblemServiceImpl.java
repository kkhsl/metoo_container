package com.metoo.nspm.core.service.zabbix.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.core.mapper.nspm.zabbix.NspmProblemMapper;
import com.metoo.nspm.core.mapper.zabbix.ProblemMapper;
import com.metoo.nspm.core.service.zabbix.IProblemService;
import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.entity.zabbix.Problem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ProblemServiceImpl implements IProblemService {

    @Autowired
    private ProblemMapper problemMapper;
    @Autowired
    private NspmProblemMapper nspmProoblemMapper;

    @Override
    public Page<Problem> selectConditionQuery(NspmProblemDTO dto) {
        if(dto == null){
            dto = new NspmProblemDTO();
        }
        Page<Problem> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.nspmProoblemMapper.selectObjConditionQuery(dto);
        return page;
    }

    @Override
    public List<Problem> selectObjByMap(Map params) {
        return this.nspmProoblemMapper.selectObjByMap(params);
    }

    @Override
    public int selectCount(Map params) {
        return this.problemMapper.selectCount(params);
    }

    @Override
    public void truncateTable() {
        this.nspmProoblemMapper.truncateTable();
    }

    @Override
    public void copyProblemTemp(Map params) {
        this.nspmProoblemMapper.copyProblemTemp(params);
    }
}
