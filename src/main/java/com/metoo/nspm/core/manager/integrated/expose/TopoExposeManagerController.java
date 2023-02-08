package com.metoo.nspm.core.manager.integrated.expose;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.ExposureDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RequestMapping("/nspm/risk")
@RestController
public class TopoExposeManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;

    @ApiOperation("防御优化-资产主机列表")
    @PostMapping(value = "/api/danger/attackSurface/hostExposureList")
    public Object statisticalInformation(@RequestBody ExposureDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/attackSurface/hostExposureList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//        @PostMapping(value="/queryNodeHistory")
//    public Object queryNodeHistory(@RequestBody TopoNodeDto dto){
//       Object result = this.httpTools.get("/topology/node/queryNodeHistory.action", dto);
//       return ResponseUtil.ok(result);
//    }
}
