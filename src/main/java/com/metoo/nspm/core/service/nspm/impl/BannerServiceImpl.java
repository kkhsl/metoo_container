package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.BannerMapper;
import com.metoo.nspm.core.service.nspm.IAccessoryService;
import com.metoo.nspm.core.service.nspm.IBannerService;
import com.metoo.nspm.dto.BannerDto;
import com.metoo.nspm.entity.nspm.Accessory;
import com.metoo.nspm.entity.nspm.Banner;
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
public class BannerServiceImpl implements IBannerService {

    @Autowired
    private BannerMapper bannerMapper;
    @Autowired
    private IAccessoryService accessoryService;

    @Override
    public Banner findObjById(Long id) {
        return this.bannerMapper.findObjById(id);
    }

    @Override
    public List<Banner> findObjByMap(Map params) {
        return this.bannerMapper.findObjByMap(params);
    }

    @Override
    public Page<Banner> query(BannerDto dto) {
        if(dto == null){
            dto = new BannerDto();
        }
        Page<Banner> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.bannerMapper.query(dto);
        return page;
    }

    @Override
    public boolean save(BannerDto dto) {
        Banner banner = null;
        if(dto.getId() == null){
            banner = new Banner();
            banner.setAddTime(new Date());
        }else{
            banner = this.bannerMapper.findObjById(dto.getId());
        }
        Accessory accessory = this.accessoryService.getObjById(dto.getAccessoryId());
        if(accessory != null){
            banner.setAccessoryId(accessory.getId());
            // 可以记录附件Path，避免联表查询时CONCAT()拼接
        }
        BeanUtils.copyProperties(dto, banner);
        if(banner.getId() == null){
            try {
                this.bannerMapper.save(banner);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                this.bannerMapper.update(banner);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public boolean update(BannerDto dto) {
        Banner banner = this.bannerMapper.findObjById(dto.getId());
        if(banner != null){
            Accessory accessory = this.accessoryService.getObjById(banner.getAccessoryId());
            if(accessory != null){
                banner.setAccessoryId(accessory.getId());
                // 可以记录附件Path，避免联表查询时CONCAT()拼接
            }
            BeanUtils.copyProperties(dto, banner);
            try {
                this.bannerMapper.update(banner);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        return false;
    }

    @Override
    public boolean delete(Long id) {
        try {
            this.bannerMapper.delete(id);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
