package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.GradeMapper;
import com.metoo.nspm.core.service.nspm.IGradeService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.GradeDto;
import com.metoo.nspm.entity.nspm.Grade;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class GradeServiceImpl implements IGradeService {

    @Autowired
    private GradeMapper gradeMapper;

    @Override
    public Grade getObjById(Long id) {
        return this.gradeMapper.selectByPrimaryKey(id);
    }

    @Override
    public List<Grade> selectAll(Map params) {
        // 分页插件: 查询第1页，每页10行
        Page<Grade> page = null;
        if(params != null && (Integer) params.get("currentPage") >= 0 && (Integer) params.get("pageSize") > 0){
            page = PageHelper.startPage((Integer) params.get("currentPage"), (Integer) params.get("pageSize"));
            this.gradeMapper.selectAll();
            return page;
        }else{
            return this.gradeMapper.selectAll();
        }
    }

    @Override
    public Object save(GradeDto instance) {
        if(instance != null){
            if(instance.getName() == null && instance.getName().equals("")){
                return ResponseUtil.result(400, "Parameter error");
            }
            try {
                Grade target = null;
                if(instance.getId() == null){
                    target = new Grade();
                    target.setAddTime(new Date());
                }else{
                    target = this.gradeMapper.selectByPrimaryKey(instance.getId());
                }
                BeanUtils.copyProperties(instance, target);
               //  grade.setAddTime(new Date());

                if(target.getId() == null){
                    this.gradeMapper.insert(target);
                }else{
                    this.gradeMapper.update(target);
                }
                return new Result(200, "Successfully");
            } catch (Exception e) {
                e.printStackTrace();
                return new Result(400, "Parameter error");
            }
        }else{
            return ResponseUtil.result(400, "Parameter error");
        }
    }

    @Override
    public Object update(Grade instance) {
        try {
            this.gradeMapper.update(instance);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean delete(Long id) {
        try {
            this.gradeMapper.deleteByPrimaryKey(id);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public Grade modify(Long id) {
        return this.gradeMapper.selectByGradeUnit(id);
    }

    @Override
    public Page<Grade> query(Map params) {
        Page<Grade> page = PageHelper.startPage((Integer) params.get("startRow"), (Integer) params.get("pageSize"));
        this.gradeMapper.query();
        return page;
    }

    @Override
    public List<Grade> findBycondition(Map params) {
        Page<Grade> page = PageHelper.startPage((Integer) params.get("currentPage"), (Integer) params.get("pageSize"));
        this.gradeMapper.findBycondition(params);
        return page;
    }

    @Override
    public List<Grade> webGradeList(Map params) {
        // 分页插件: 查询第1页，每页10行
        Page<Grade> page = null;
        if (params != null && (Integer) params.get("currentPage") >= 0 && (Integer) params.get("pageSize") > 0) {
            page = PageHelper.startPage((Integer) params.get("currentPage"), (Integer) params.get("pageSize"));
            this.gradeMapper.webGradeList();
            return page;
        } else {
            return this.gradeMapper.webGradeList();
        }
    }

}
