package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.service.nspm.IBannerService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Banner;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("banner")
@RequestMapping("/web/banner")
@RestController
public class BannerViewController {

    @Autowired
    private ISysConfigService configService;
    @Autowired
    private IBannerService bannerService;

    @RequestMapping("/carousel")
    public Object list(){
        Map params = new HashMap();
        params.put("display", 1);
        List<Banner> bannerList = this.bannerService.findObjByMap(params);
        if(bannerList.size() > 0){
            Map data = new HashMap();
            data.put("obj", bannerList);
            return ResponseUtil.ok(data);
        }
        return ResponseUtil.ok();
    }
}
