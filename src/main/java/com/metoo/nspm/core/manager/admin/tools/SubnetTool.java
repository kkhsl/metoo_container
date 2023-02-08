package com.metoo.nspm.core.manager.admin.tools;

import com.metoo.nspm.core.service.nspm.ZabbixSubnetService;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.entity.nspm.Subnet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class SubnetTool {

    @Autowired
    private ZabbixSubnetService subnetService;
    @Autowired
    private ZabbixSubnetService zabbixSubnetService;

    /**
     * 验证Ip是否属于子网
     * @param subnet
     * @param ip
     * @return
     */
    public Subnet verifySubnetByIp(Subnet subnet, String ip){
        List<Subnet> childs = this.subnetService.selectSubnetByParentId(subnet.getId());
        if(childs.size() > 0){
            for(Subnet child : childs){
                Subnet csubnet = verifySubnetByIp(child, ip);
                if(csubnet != null){
                    return csubnet;
                }
            }
        }else{
            // 判断ip是否属于从属子网
            boolean flag = IpUtil.ipIsInNet(ip, subnet.getIp() + "/" + subnet.getMask());
            if(flag){
                return subnet;
            }
        }
        return null;
    }

    /**
     * 验证Ip属于哪个网段，并返回网络地址和广播地址
     * @param ip
     * @return
     */
    public Map verifyIpBelongSubnet(String ip){
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
        if(subnets.size() > 0){
            if(ip != null){
                if(ip.equals("0.0.0.0")){
                }
                if(!IpUtil.verifyIp(ip)){
                }
                // 判断ip地址是否属于子网
                for(Subnet subnet : subnets){
                    Subnet sub = verifySubnetByIp(subnet, ip);
                    if(sub != null){
                        String mask = IpUtil.bitMaskConvertMask(sub.getMask());
                        return IpUtil.getNetworkIpDec(sub.getIp(), mask);

                    }
                }
            }
        }
        return new HashMap();
    }
}
