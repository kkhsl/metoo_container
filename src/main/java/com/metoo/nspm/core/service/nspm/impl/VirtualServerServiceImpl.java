package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.VirtualServerMapper;
import com.metoo.nspm.core.service.nspm.IOperationSystemService;
import com.metoo.nspm.core.service.nspm.IRsmsDeviceService;
import com.metoo.nspm.core.service.nspm.IVirtualServerService;
import com.metoo.nspm.core.service.nspm.IVirtualTypeService;
import com.metoo.nspm.dto.VirtualServerDto;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.entity.nspm.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Map;

@Service
@Transactional
public class VirtualServerServiceImpl implements IVirtualServerService {

    @Autowired
    private VirtualServerMapper virtualServerMapper;
    @Autowired
    private IVirtualTypeService virtualTypeService;
    @Autowired
    private IOperationSystemService operationSystemService;
    @Autowired
    private IRsmsDeviceService rsmsDeviceService;

    @Override
    public VirtualServer getObjById(Long id) {
        return this.virtualServerMapper.getObjById(id);
    }

    @Override
    public Page<VirtualServer> selectList(VirtualServerDto instance) {
        User user = ShiroUserHolder.currentUser();
        instance.setUserId(user.getId());
        Page<VirtualServer> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.virtualServerMapper.selectList(instance);
        return page;
    }

    @Override
    public int insert(VirtualServer instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
        }
        User user = ShiroUserHolder.currentUser();
        if(user != null){
            instance.setUserId(user.getId());
            instance.setUserName(user.getUsername());
        }
        // 验证虚拟化类型
        VirtualType virtualType = this.virtualTypeService.getObjById(instance.getVirtual_type_id());
        if(virtualType != null){
            instance.setVirtual_type_id(virtualType.getId());
            instance.setVirtual_type_name(virtualType.getName());
        }
        // 验证操作系统
        OperationSystem operationSystem = this.operationSystemService.getObjById(instance.getOperation_system_id());
        if(operationSystem != null){
            instance.setOperation_system_id(operationSystem.getId());
            instance.setOperation_system_name(operationSystem.getName());
        }

        // 验证设备
        RsmsDevice rsmsDevice = this.rsmsDeviceService.getObjById(instance.getDevice_id());
        if (rsmsDevice != null){
            instance.setDevice_id(rsmsDevice.getId());
            instance.setDevice_name(rsmsDevice.getName());
        }

        if(instance.getId() == null){
            return this.virtualServerMapper.insert(instance);
        }else{
            return this.virtualServerMapper.update(instance);
        }

    }

    @Override
    public int update(VirtualServer instance) {
        return 0;
    }

    @Override
    public int deleteById(Long id) {
        return this.virtualServerMapper.deleteById(id);
    }

    @Override
    public int deleteByMap(Map map) {
        return this.virtualServerMapper.deleteByMap(map);
    }
}
