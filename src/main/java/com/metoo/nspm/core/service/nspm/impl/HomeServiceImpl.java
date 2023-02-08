package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.HomeMapper;
import com.metoo.nspm.core.service.nspm.IHomeService;
import com.metoo.nspm.entity.nspm.Home;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class HomeServiceImpl implements IHomeService {

    @Autowired
    private HomeMapper homeMapper;

    @Override
    public List<Home> selectObjByMap(Map map) {
        return this.homeMapper.selectObjByMap(map);
    }

    @Override
    public int save(Home instance) {
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
        }
        if(instance.getId() == null || instance.getId().equals("")){
            try {
                return this.homeMapper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.homeMapper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }

    }

    @Override
    public int update(Home instance) {
        try {
            return this.homeMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        return this.homeMapper.delete(id);
    }
}
