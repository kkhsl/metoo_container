package com.metoo.nspm.core.manager.admin.action;

import com.github.pagehelper.Page;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.RoutTool;
import com.metoo.nspm.core.manager.admin.tools.SubnetTool;
import com.metoo.nspm.core.service.nspm.IIPAddressService;
import com.metoo.nspm.core.service.nspm.IRoutService;
import com.metoo.nspm.core.service.nspm.IRoutTableService;
import com.metoo.nspm.core.service.nspm.ZabbixSubnetService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.Route;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/admin/rout")
@RestController
public class RoutManagerController {

    @Autowired
    private IRoutService routService;
    @Autowired
    private IRoutTableService routTableService;
    @Autowired
    private IIPAddressService ipAddressServie;
    @Autowired
    private ZabbixSubnetService subnetService;
    @Autowired
    private SubnetTool subnetTool;
    @Autowired
    private RoutTool routTool;

//    @RequestMapping("/routTable")
//    public Object routTable(String srcIp, Integer srcMask, String destIp, Integer destMask){
//        if(StringUtil.isEmpty(srcIp)){
//            return ResponseUtil.badArgument("起点Ip不能为空");
//        }
//        if(!IpUtil.verifyIp(srcIp)){
//            return ResponseUtil.badArgument("起点Ip格式错误");
//        }
//        if(StringUtil.isEmpty(destIp)){
//            return ResponseUtil.badArgument("终点Ip不能为空");
//        }
//        if(!IpUtil.verifyIp(destIp)){
//            return ResponseUtil.badArgument("终点Ip格式错误");
//        }
//        Map origin =  null;
//        List<Subnet> subnets = this.subnetService.selectSubnetByParentId(null);
//        if(subnets.size() > 0){
//            if(srcIp != null){
//                if(srcIp.equals("0.0.0.0")){
//                }
//                if(!IpUtil.verifyIp(srcIp)){
//                }
//                // 判断ip地址是否属于子网
//                for(Subnet subnet : subnets){
//                    Subnet sub = this.subnetTool.verifySubnetByIp(subnet, srcIp);
//                    if(sub != null){
//                        String mask = IpUtil.bitMaskConvertMask(sub.getMask());
//                        origin = IpUtil.getNetworkIpDec(sub.getIp(), mask);
//                        break;
//                    }
//                }
//            }
//        }
//        if(origin == null || origin.isEmpty()){
//            return ResponseUtil.badArgument("起点Ip不存在");
//        }
//        IpAddress srcIpAddress = this.ipAddressServie.querySrcDevice(origin);
//        if(srcIpAddress == null){
//            return ResponseUtil.badArgument("起点Ip不存在");
//        }
//
//        Map map = new HashMap();
//        Map dest = null;
//        // 获取起点ip网络地址和广播地址
//        if(subnets.size() > 0){
//            if(destIp != null){
//                if(destIp.equals("0.0.0.0")){
//                }
//                if(!IpUtil.verifyIp(destIp)){
//                }
//                // 判断ip地址是否属于子网
//                for(Subnet subnet : subnets){
//                    Subnet sub = this.subnetTool.verifySubnetByIp(subnet, destIp);
//                    if(sub != null){
//                        String mask = IpUtil.bitMaskConvertMask(sub.getMask());
//                        dest = IpUtil.getNetworkIpDec(sub.getIp(), mask);
//                        break;
//                    }
//                }
//            }
//        }
//        if(dest == null || dest.isEmpty()){
//            return ResponseUtil.badArgument("终点Ip不存在");
//        }
//        // 终点设备
//        IpAddress destIpAddress = this.ipAddressServie.querySrcDevice(dest);
//        if(destIpAddress == null){
//            return ResponseUtil.badArgument("终点Ip不存在");
//        }
//        map.put("destinationDevice", destIpAddress);
//        this.routTableService.truncateTable();
//        Map params = new HashMap();
//        // 保存起点设备
//        params.clear();
//        params.put("ip", srcIpAddress.getIp());
//        params.put("mask", srcIpAddress.getMask());
//        params.put("deviceName", srcIpAddress.getDeviceName());
//        params.put("interfaceName", srcIpAddress.getInterfaceName());
//        params.put("mac", srcIpAddress.getMac());
//        List<RouteTable> routTables = this.routTableService.selectObjByMap(params);
//        RouteTable routTable = null;
//        if(routTables.size() > 0){
//            routTable = routTables.get(0);
//        }else{
//            routTable = new RouteTable();
//        }
//        String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
//        BeanUtils.copyProperties(srcIpAddress, routTable, IGNORE_ISOLATOR_PROPERTIES);
//        this.routTableService.save(routTable);
//        /*List<IpAddress> ipAddresses = */
//        this.routTool.generatorRout(srcIpAddress, destIp, destIpAddress.getMask());
//        List<RouteTable> routTableList = this.routTableService.selectObjByMap(null);
//        map.put("destinationDevice", destIpAddress);
//        map.put("routTable", routTableList);
//        return ResponseUtil.ok(map);
//    }

    @ApiOperation("设备路由列表")
    @PostMapping("/device/rout")
    public Object deviceRoutList(@RequestBody RoutDTO dto){
        if(StringUtil.isEmpty(dto.getDeviceUuid())){
            return ResponseUtil.badArgument();
        }
        Page<Route> page = this.routService.selectConditionQuery(dto);
        if(page.getResult().size() > 0) {
            return ResponseUtil.ok(new PageInfo<Route>(page));
        }
        return ResponseUtil.ok();
    }



}
