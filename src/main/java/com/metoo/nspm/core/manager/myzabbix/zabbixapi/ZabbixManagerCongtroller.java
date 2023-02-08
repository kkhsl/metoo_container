package com.metoo.nspm.core.manager.myzabbix.zabbixapi;

import com.metoo.nspm.core.manager.myzabbix.utils.ItemUtil;
import com.metoo.nspm.core.mapper.nspm.zabbix.ArpHistoryMapper;
import com.metoo.nspm.core.mapper.nspm.zabbix.MacHistoryMapper;
import com.metoo.nspm.core.mapper.nspm.zabbix.RouteHistoryMapper;
import com.metoo.nspm.core.service.api.zabbix.ZabbixService;
import com.metoo.nspm.core.service.nspm.IRoutService;
import com.metoo.nspm.core.service.zabbix.IGatherService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Route;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.URLDecoder;
import java.util.*;
import java.util.List;

@RequestMapping("/zabbix")
@RestController
public class ZabbixManagerCongtroller {

    @Autowired
    private ZabbixService zabbixService;
    @Autowired
    private ItemUtil itemUtil;
    @Autowired
    private IRoutService routService;
    @Autowired
    private ArpHistoryMapper arpHistoryMapper;
    @Autowired
    private MacHistoryMapper macHistoryMapper;
    @Autowired
    private RouteHistoryMapper routHistoryMapper;
    @Autowired
    private IGatherService gatherArpItem;

    public static void main(String[] args) {
//        Long id = ((User)r).getGroupId();
//        System.out.println(id);
    }

    @RequestMapping("/getsystem")
    public Object getSystem(HttpServletRequest request ){
        Map map = new HashMap();
        try {
            String resourceUtilUrl = ResourceUtils.getURL("classpath:").getPath() + "static/routs" + "/routTable.conf";
            map.put("resourceUtilUrl", URLDecoder.decode(resourceUtilUrl, "utf-8"));
            String contextPath = request.getContextPath();
            map.put("contextPath", contextPath);
            String servletContextPath = request.getServletContext().getContextPath();
            map.put("servletContextPath", servletContextPath);
            String realPath = request.getServletContext().getRealPath("/");
            map.put("realPath", realPath);
            String realPath2 = request.getServletContext().getRealPath("");
            map.put("realPath2", realPath2);

            Resource resource = new ClassPathResource("");
            map.put("resource", resource.getFile().getAbsolutePath());
            return map;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    @ApiOperation("采集Arp")
    @RequestMapping("/arp")
    public void getArp() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.zabbixService.gatherArp(cal.getTime());
    }

    @ApiOperation("采集Arp")
    @RequestMapping("/arp2")
    public void getArp2() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.zabbixService.gatherArp(cal.getTime());
    }

    @ApiOperation("采集Arp")
    @RequestMapping("/arp3")
    public void getArp3() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.gatherArpItem.gatherArpItem(cal.getTime());
    }

    @ApiOperation("采集Mac")
    @RequestMapping("/mac3")
    public void getmac3() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.gatherArpItem.gatherMacItem(cal.getTime());
    }

    @ApiOperation("采集Route")
    @RequestMapping("/route3")
    public void route3() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.gatherArpItem.gatherRouteItem(cal.getTime());
    }

    @ApiOperation("采集IpAddress")
    @RequestMapping("/ipAddress3")
    public void ipAddress3() {
        Calendar cal = Calendar.getInstance();// 设置采集时间
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.gatherArpItem.gatherIpaddressItem(cal.getTime());
    }

    @RequestMapping("/arpThread")
    public void arpThread() {
        this.zabbixService.gatherArpThread();
    }

    @RequestMapping("/mac")
    public void getMac(){
        Calendar cal = Calendar.getInstance();
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.zabbixService.gatherMac(cal.getTime());
    }


    @RequestMapping("/arpMac")
    public Object get(){
        this.zabbixService.gatherArpThread();
        this.zabbixService.gatherMacThread();
        return "ok";
    }

    @RequestMapping("/problem")
    public void getProblem() {
        this.zabbixService.gatherProblem();
    }

    @ApiOperation("采集Ipaddrss")
    @GetMapping(value = {"/ipaddress"})
    public Object ipaddress() {
        Calendar cal = Calendar.getInstance();
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);

        this.zabbixService.gatherIp(cal.getTime());
        return ResponseUtil.ok();
    }

    @ApiOperation("采集Rout")
    @GetMapping(value = {"/rout"})
    public Object rout(HttpServletRequest request) throws IOException {
        Calendar cal = Calendar.getInstance();
        cal.clear(Calendar.SECOND);
        cal.clear(Calendar.MILLISECOND);
        this.zabbixService.gatherRout(cal.getTime());
        return ResponseUtil.ok();
    }


    @ApiOperation("Arp历史")
    @GetMapping(value = {"/arpHistory"})
    public Object arpHistory() throws IOException {
        this.arpHistoryMapper.copyArpTemp();
        return ResponseUtil.ok();
    }

    @ApiOperation("Mac历史")
    @GetMapping(value = {"/macHistory"})
    public Object macHistory() throws IOException {
        this.macHistoryMapper.copyMacTemp();
        return ResponseUtil.ok();
    }

    @ApiOperation("Rout历史")
    @GetMapping(value = {"/routHistory"})
    public Object routHistory() throws IOException {
        this.routHistoryMapper.copyRoutTemp();
        return ResponseUtil.ok();
    }



//    @ApiOperation("采集Rout")
//    @GetMapping(value = {"/rout"})
//    public Object rout(HttpServletRequest request) throws IOException {
//        List<Map> ipList = this.topoNodeService.query();
//        if(ipList != null && ipList.size() > 0) {
//            // truncate
//            this.ipaddressService.truncateTable();
//            this.routService.truncateTable();
//            for (Map map : ipList) {
//                boolean flag = this.zabbixHostService.verifyHost(String.valueOf(map.get("ip")));
//                if (flag) {
//                    System.out.println(map.get("ip").toString());
////                    this.zabbixService.gatherIpaddress(map.get("ip").toString(), map.get("deviceName").toString());
//                    this.zabbixService.gatherRout(map.get("ip").toString(), map.get("deviceName").toString());
//                }
//            }
//        }
//        return ResponseUtil.ok();
//    }

    @ApiOperation("获取路由表")
    @GetMapping(value = {"/static/routs/{ip}", "/static/routs"})
    public Object rout(HttpServletRequest request, @PathVariable("ip") String ip) throws IOException {
        String path = ResourceUtils.getURL("classpath:").getPath() + "/static/routs/routTable.conf";
        path = "C:\\Users\\46075\\Desktop\\metoo\\需求记录\\4，策略可视化\\监控系统（Zabbix）\\routTable.conf";
        File file = new File(URLDecoder.decode(path, "utf-8"));
        FileWriter fileWriter =new FileWriter(file);
        fileWriter.write("");
        fileWriter.flush();
        fileWriter.close();
        Writer out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file,true),"utf-8"), 1024*1000);
        out.write("display ip routing-table");
        out.write("\r\n");
        out.write(itemUtil.strLenComplement("Destination/Mask", 25));
        out.write(itemUtil.strLenComplement("Proto", 10));
        out.write(itemUtil.strLenComplement("Pre", 10));
        out.write(itemUtil.strLenComplement("Cost", 10));
        out.write(itemUtil.strLenComplement("Flags", 10));
        out.write(itemUtil.strLenComplement("NextHop", 30));
        out.write(itemUtil.strLenComplement("interface", 20));
        out.write("\r\n");
        List<Map<String, String>> maps = this.zabbixService.getItemRoutByIp(ip);
        Map params = new HashMap();
        if(!maps.isEmpty() && maps.size()>0){
            this.routService.truncateTable();
            for (Map<String, String> map : maps){
                out.write(itemUtil.strLenComplement(map.get("destination") + "/" + map.get("mask"), 25));
                out.write(itemUtil.strLenComplement(map.get("proto"), 10));
                out.write(itemUtil.strLenComplement("0", 10));
                out.write(itemUtil.strLenComplement(map.get("routemetric") == null ? "0" : map.get("routemetric"), 10));
                out.write(itemUtil.strLenComplement(map.get("flags"), 10));
                out.write(itemUtil.strLenComplement(map.get("nextHop"), 30));
                out.write(itemUtil.strLenComplement(map.get("interfaceName") == null ? "" : map.get("interfaceName"), 20));
                out.write("\r\n");
                params.clear();
                params.put("interfaceName", map.get("interface_name"));
                try {
                    Route rout = new Route();
                    rout.setDestination(map.get("destination"));
                    rout.setMask(map.get("mask"));
                    rout.setCost(map.get("routemetric"));
                    rout.setFlags(map.get("flags"));
                    rout.setInterfaceName(map.get("interfaceName"));
                    rout.setProto(map.get("proto"));
                    rout.setNextHop(map.get("nextHop"));
                    this.routService.save(rout);
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                }
            }
        }
        out.flush();
        out.close();
        return maps;
    }

}
