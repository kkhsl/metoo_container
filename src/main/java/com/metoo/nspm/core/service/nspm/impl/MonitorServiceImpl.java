package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.MonitorMapper;
import com.metoo.nspm.core.service.nspm.IMonitorService;
import com.metoo.nspm.dto.MonitorDto;
import com.metoo.nspm.entity.nspm.Monitor;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.text.SimpleDateFormat;
import java.util.Date;

@Service
@Transactional
public class MonitorServiceImpl implements IMonitorService {

    @Autowired
    private MonitorMapper monitorMapper;

    @Override
    public Monitor getObjById(Long id) {
        return monitorMapper.getObjById(id);
    }

    @Override
    public Monitor getObjBySign(String sign) {
        return monitorMapper.getObjBySign(sign);
    }

    @Override
    public Page<Monitor> query(MonitorDto dto) {
        Page<Monitor> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.monitorMapper.query(dto);
        return page;
    }

    @Override
    public boolean save(MonitorDto instance) {
//        Monitor monitor = null;
        // 1, 根据签名查询该记录是否已记录,无：直接记录直播信息 有：关闭直播
        Monitor monitor = this.getObjBySign(instance.getSign());
        if(monitor == null){
            // 直播开始
            monitor = new Monitor();
            monitor.setAddTime(new Date());
            monitor.setStatus(1);
        }else{
            // 直播结束
            monitor.setStatus(0);
            monitor.setEndTime(new Date());
       }
        BeanUtils.copyProperties(instance, monitor);
        if(monitor.getId() ==  null){
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy -MM-dd HH:mm:ss");
                long startTime = Long.parseLong(instance.getStartTime());
                Date date = new Date(startTime);
                monitor.setStartTime(date);
                this.monitorMapper.save(monitor);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                this.monitorMapper.update(monitor);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public boolean update(MonitorDto instance) {
        Monitor monitor = new Monitor();
        BeanUtils.copyProperties(instance, monitor);
        try {
            this.monitorMapper.update(monitor);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public int delete(Long id) {
        return this.monitorMapper.delete(id);
    }
}
