package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.CourseMapper;
import com.metoo.nspm.core.service.nspm.ICourseService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.CourseDto;
import com.metoo.nspm.entity.nspm.Course;
import com.metoo.nspm.vo.CourseVo;
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
public class CourseServiceImpl implements ICourseService {

    @Autowired
    private CourseMapper courseMapper;

    @Override
    public Course getObjById(Long id) {
        return this.courseMapper.selectByPrimaryKey(id);
    }

    @Override
    public Page<Course> query(Map params) {
        // 分页插件: 查询第1页，每页10行
         Page<Course> page = PageHelper.startPage((Integer) params.get("startRow"), (Integer) params.get("pageSize"));
          this.courseMapper.query();
          return page;

    }

    @Override
    public Object save(CourseDto instance) {
        if(instance.getName() == null){
            return ResponseUtil.result(400, "Name is not null");
        }
        Course target = null;
        if(instance.getId() == null){
            target = new Course();
            target.setAddTime(new Date());
        }else{
            target = this.courseMapper.selectByPrimaryKey(instance.getId());
        }
        BeanUtils.copyProperties(instance, target);
        if(instance.getId() == null){
            try {
                this.courseMapper.insert(target);
                return ResponseUtil.add();
            } catch (Exception e) {
                e.printStackTrace();
                return ResponseUtil.error();
            }
        }else{
            try {
                this.courseMapper.update(target);
                return ResponseUtil.update();
            } catch (Exception e) {
                e.printStackTrace();
                return ResponseUtil.error();
            }
        }
    }

    @Override
    public Object update(Course instance) {
        if(instance.getName() == null){
            return ResponseUtil.result(400, "Name is not null");
        }
        try {
            this.courseMapper.update(instance);
            return ResponseUtil.result(200, "Successfully");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseUtil.result(500, "Fail to update");
        }
    }

    @Override
    public boolean delete(Long id) {
        try {
            this.courseMapper.deleteByPrimaryKey(id);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    @Override
    public List<Course> selectAll() {
        return this.courseMapper.queryAll();
    }

    @Override
    public List<CourseVo> webCourseList() {
        return this.courseMapper.webCourseList();
    }

    @Override
    public List<Course> findBycondition(Map params) {
        Page<Course> page = null;
        if(params != null && (Integer) params.get("currentPage") >= 0 && (Integer) params.get("pageSize") > 0) {
            page = PageHelper.startPage((Integer) params.get("currentPage"), (Integer) params.get("pageSize"));
            this.courseMapper.findBycondition(params);
            return page;
        }
        return this.courseMapper.findBycondition(params);
    }


}
