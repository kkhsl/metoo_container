package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IAddressService;
import com.metoo.nspm.core.service.nspm.IpDetailService;
import com.metoo.nspm.core.service.nspm.ZabbixSubnetService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.Address;
import com.metoo.nspm.entity.nspm.IpDetail;
import com.metoo.nspm.entity.nspm.Subnet;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/admin/address")
@RestController
public class AddressManagerController {

    @Autowired
    private IAddressService addressService;
    @Autowired
    private ZabbixSubnetService zabbixSubnetService;
    @Autowired
    private IpDetailService ipDetailService;

    /**
     * 创建子网Ip地址
     * @param address
     * @return
     */
    @PostMapping
    public Object save(@RequestBody(required = false) Address address){
        Subnet subnet = this.zabbixSubnetService.selectObjById(address.getSubnetId());
        if(subnet != null){
            if(address.getId() != null){
                Address obj = this.addressService.selectObjById(address.getId());
                if(obj == null){
                    return ResponseUtil.badArgument();
                }
            }
            if(address.getIp() != null){
                if(!IpUtil.verifyIp(subnet.getIp())){
                    return ResponseUtil.badArgument("ip格式错误");
                }
                // 判断ip地址是否属于子网
                boolean flag = IpUtil.ipIsInNet(address.getIp(), subnet.getIp() + "/" + subnet.getMask());
                if(!flag){
                    return ResponseUtil.badArgument("ip地址不在子网边界内");
                }
                Address obj = this.addressService.selectObjByIp(IpUtil.ipConvertDec(address.getIp()));
                if(obj != null){
                    // copy数据到obj，然后更新
                    String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
                    BeanUtils.copyProperties(address, obj, IGNORE_ISOLATOR_PROPERTIES);
                    obj.setIp(IpUtil.ipConvertDec(obj.getIp()));
                    int i = this.addressService.save(obj);
                    if(i >= 1){
                        return ResponseUtil.ok();
                    }
                    return ResponseUtil.error();
                }else{
                    // 创建ip_detail
                    IpDetail ipDetail = new IpDetail();
                    ipDetail.setDeviceName(address.getHostName());
                    ipDetail.setMac(address.getMac());
                    ipDetail.setOnline(true);
                    ipDetail.setIp(IpUtil.ipConvertDec(address.getIp()));
                    this.ipDetailService.save(ipDetail);
                }
            }
            address.setIp(IpUtil.ipConvertDec(address.getIp()));
            int i = this.addressService.save(address);
            if(i >= 1){
                return ResponseUtil.ok();
            }
            return ResponseUtil.error();
        }
        return ResponseUtil.badArgument("请选择子网");
    }

    @DeleteMapping
    public Object delete(@RequestParam(value = "id") Long id){
        Address address = this.addressService.selectObjById(id);
        if(address != null){
            int i = this.addressService.delete(address.getId());
            if(i >= 1){
                return ResponseUtil.ok();
            }
            return ResponseUtil.error();
        }
        return ResponseUtil.badArgument();
    }

}
