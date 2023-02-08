package com.metoo.nspm.core.manager.admin.action;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.*;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.file.DownLoadFileUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.TopologyDTO;
import com.github.pagehelper.Page;
import com.metoo.nspm.dto.zabbix.RoutDTO;
import com.metoo.nspm.entity.nspm.*;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@RequestMapping("/admin/topology")
@RestController
public class TopologyManagerController {

    @Autowired
    private ITopologyService topologyService;
    @Autowired
    private ITopologyHistoryService topologyHistoryService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;
    @Autowired
    private IPresetPathService presetPathService;
    @Autowired
    private IRoutService routService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private IArpService arpService;
    @Autowired
    private IArpHistoryService arpHistoryService;
    @Autowired
    private IIPAddressService ipAddressServie;
    @Autowired
    private IIPAddressHistoryService ipAddressHistoryServie;
    @Autowired
    private IRoutTableService routTableService;
    @Autowired
    private IRoutHistoryService routHistoryService;
    @Autowired
    private ZabbixSubnetService zabbixSubnetService;
    @Autowired
    private INetworkElementService networkElementService;
    @Autowired
    private SubnetTool subnetTool;
    @Autowired
    private RoutTool routTool;

    @RequestMapping("/list")
    public Object list(@RequestBody(required = false) TopologyDTO dto){
        if(dto == null){
            dto = new TopologyDTO();
        }
        User user = ShiroUserHolder.currentUser();
        if(dto.getGroupId() == null){
            dto.setGroupId(user.getGroupId());
        }
        if(dto.getGroupId() != null){
            Group group = this.groupService.selectObjById(dto.getGroupId());
            if(group != null){
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                dto.setGroupIds(ids);
            }
        }
        Page<Topology> page = this.topologyService.selectConditionQuery(dto);
        if(page.getResult().size() > 0) {
           if(page.getResult().size() == 1){
               // 设置默认拓扑
               try {
                   this.setTopologyDefualt();
               } catch (Exception e) {
                   e.printStackTrace();
               }
           }
            return ResponseUtil.ok(new PageInfo<Topology>(page));
        }
        return ResponseUtil.ok();
    }

    @GetMapping("/add")
    public Object add(){
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        Group parent = this.groupService.selectObjById(user.getGroupId());
        List<Group> groupList = new ArrayList<>();
        if(parent != null){
            this.groupTools.genericGroup(parent);
            groupList.add(parent);
        }
        map.put("group", groupList);
        return ResponseUtil.ok(map);
    }

    @GetMapping("/update")
    public Object update(Long id){
        if(id == null){
            return  ResponseUtil.badArgument();
        }
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        Group parent = this.groupService.selectObjById(user.getGroupId());
        List<Group> groupList = new ArrayList<>();
        if(parent != null){
            this.groupTools.genericGroup(parent);
            groupList.add(parent);
        }
        return ResponseUtil.ok(map);
    }

    @ApiOperation("拓扑修改名称")
    @GetMapping("/rename")
    public Object rename(Long id, String name){
        if(name == null || name.equals("")){
            return  ResponseUtil.badArgument("拓扑名称不能为空");
        }
        Map params = new HashMap();
//        params.put("id", id);
        params.put("name", name);
        params.put("NotId", id);
        List<Topology> topologies = this.topologyService.selectObjByMap(params);
        if(topologies.size() > 0){
            return  ResponseUtil.badArgument("拓扑名称已存在");
        }else{
            if(name != null && !name.equals("")){
                Topology topology = this.topologyService.selectObjById(id);
                if(topology != null){
                    topology.setName(name);
                    if(topology.getSuffix() != null && !topology.getSuffix().equals("")){
                        topology.setSuffix(null);
                    }
                    int i = this.topologyService.update(topology);
                    if(i == 1){
                        return ResponseUtil.ok();
                    }else{
                        return ResponseUtil.error();
                    }
                }else{
                    return  ResponseUtil.resourceNotFound();
                }
            }
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("拓扑复制")
    @GetMapping("/copy")
    public Object copy(String id, String name, String groupId){
        Map params = new HashMap();
        if(name != null && !name.equals("")){
            params.clear();
            params.put("name", name);
            params.put("NotId", id);
            List<Topology> Topos = this.topologyService.selectObjByMap(params);
            if(Topos.size() > 0){
                return  ResponseUtil.badArgument("拓扑名称已存在");
            }
        }
        // 分组
        Group group = this.groupService.selectObjById(Long.parseLong(groupId));
        if(group == null){
            return ResponseUtil.badArgument("分组不存在");
        }
        params.clear();
        params.put("id", id);
        List<Topology> topologies = this.topologyService.selectObjByMap(params);
        if(topologies.size() > 0){
            Topology copyTopology = topologies.get(0);
            Long returnId = this.topologyService.copy(copyTopology);
            if(returnId != null){
                Topology topology = this.topologyService.selectObjById(Long.parseLong(String.valueOf(returnId)));
                if(topology != null){
                    if(name != null && !name.equals("")){
                        topology.setName(name);
                    }else{
                        String suffix = this.changName(copyTopology.getSuffix(), 1);
                        topology.setSuffix(suffix);
                    }
                    topology.setGroupId(group.getId());
                    topology.setGroupName(group.getBranchName());
                    this.topologyService.update(topology);
                    return ResponseUtil.ok();
                }
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

    @RequestMapping("/test")
    public void test(String name){
        this.changName(name, 1);
    }


    public String changName(String suffix, int num){
        if(suffix == null || suffix.equals("")){
            int number = num;
            if(number == 0){
                number = 1;
            }
            String name = "副本" + " (" + number + ")";
            Topology topology = this.topologyService.selectObjBySuffix(name);
            if(topology != null){
                number ++;
               return this.changName(null, number);
            }
            return name;
        }else{
            int number = num;
            if(number == 0){
                number = 1;
            }
            String name = suffix + " 副本 (" + number + ")";
            Topology topology = this.topologyService.selectObjBySuffix(name);
            if(topology != null){
                number ++;
                return this.changName(suffix, number);
            }
            return name;
        }
    }

    @ApiOperation("保存拓扑")
    @RequestMapping("/save")
    public Object save(@RequestBody(required = false) Topology instance){
        // 校验拓扑名称是否重复
        Map params = new HashMap();
        params.put("topologyId", instance.getId());
        params.put("name", instance.getName());
        List<Topology> topologList = this.topologyService.selectObjByMap(params);
        if(topologList.size() > 0){
            return ResponseUtil.badArgument("拓扑名称重复");
        }
        // 校验分组
        if(instance.getGroupId() != null){
            Group group = this.groupService.selectObjById(instance.getGroupId());
            if(group != null){
                instance.setGroupId(group.getId());
                instance.setGroupName(group.getBranchName());
            }
        }else{
            User user = ShiroUserHolder.currentUser();
            Group group = this.groupService.selectObjById(user.getGroupId());
            if(group != null){
                instance.setGroupId(group.getId());
                instance.setGroupName(group.getBranchName());
            }
        }
        if(instance != null && !instance.getContent().equals("")){
            String str = JSONObject.toJSONString(instance.getContent());
            instance.setContent(str);
        }
        int result = this.topologyService.save(instance);
        if(result >= 1){
            // 设置默认拓扑
            try {
                this.setTopologyDefualt();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.badArgument();
    }

    @DeleteMapping("/delete")
    public Object delete(String ids){
        if(ids != null && !ids.equals("")){
            for (String id : ids.split(",")){
                Topology obj = this.topologyService.selectObjById(Long.parseLong(id));
                if(obj.getIsDefault()){
                    return ResponseUtil.badArgument("拓扑【" + obj.getName() + "】为默认地址");
                }
                Map params = new HashMap();
                try {
                    User user = ShiroUserHolder.currentUser();
                    List<Topology> topologies = this.selectObjById(user, obj.getId(), null);
                    if(topologies != null && topologies.size() >= 1){
                        int i = this.topologyService.delete(obj.getId());
                        if(i >= 1){
                            // 设置默认拓扑
                            try {
                                this.setTopologyDefualt();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            if(obj != null){
                                params.clear();
                                params.put("topologyId", obj.getId());
                                List<PresetPath> presetPaths = this.presetPathService.selectObjByMap(params);
                                for(PresetPath presetPath : presetPaths){
                                    try {
                                        presetPath.setTopologyName(null);
                                        presetPath.setTopologyId(null);
                                        this.presetPathService.update(presetPath);
//                                        this.presetPathService.delete(presetPath.getId());
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        }
                    }else{
                        return ResponseUtil.badArgument();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return ResponseUtil.ok("拓扑【" + obj.getName() + "】删除失败");
                }
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument();
    }

    /**
     * 设置乐观锁，多用户同时登陆，避免并发提交
     * @param id
     * @return
     */
    @ApiOperation("设置默认拓扑")
    @RequestMapping("/default")
    public Object isDefault(String id){
        Topology obj = this.topologyService.selectObjById(Long.parseLong(id));
        if(obj != null){
            obj.setIsDefault(true);
            User user = ShiroUserHolder.currentUser();
            List<Topology> topologyList = this.defaultList(user, true);
            if(topologyList.size() > 0){
                Topology topology = topologyList.get(0);
                if(obj == topology){
                    return ResponseUtil.ok();
                }else{
                    topology.setIsDefault(false);
                    this.topologyService.update(topology);
                }
            }
            this.topologyService.update(obj);
            return ResponseUtil.ok();
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("拓扑信息")
    @GetMapping("/info")
    public Object info(
                        @RequestParam(value = "id") Long id,
                        @DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
                        @RequestParam(value = "time", required = false) Date time){
        if(id == null){
            return  ResponseUtil.badArgument();
        }
        User user = ShiroUserHolder.currentUser();
        List<Topology> topologies = selectObjById(user, id, time);
        if(topologies != null && topologies.size() > 0){
            Topology topology = topologies.get(0);
            if(topology.getContent() != null && !topology.getContent().equals("")){
                JSONObject content = JSONObject.parseObject(topology.getContent().toString());
                topology.setContent(content);
            }
            return ResponseUtil.ok(topology);
        }
        return ResponseUtil.ok();
    }

    @ApiOperation("默认拓扑")
    @GetMapping("/default/topology")
    public Object defaultTopology(){
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null){
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
            params.put("isDefault", true);
            List<Topology> topologies = this.topologyService.selectObjByMap(params);
            if (topologies.size() > 0){
                Topology topology = topologies.get(0);
                if(topology.getContent() != null && !topology.getContent().equals("")){
                    System.out.println(JSON.toJSONString(topology.getContent()));
                    JSONObject content = JSONObject.parseObject(topology.getContent().toString());
                    topology.setContent(content);
                }
                map.put("topology", topologies.get(0));
                return ResponseUtil.ok(map);
            }
        }
        return ResponseUtil.ok(map);
    }


    @ApiOperation("拓扑路径列表")
    @PostMapping("/path")
    public Object path(@RequestParam(value = "id") Long id){
        // 是否改为当前用户所在组
        User user = ShiroUserHolder.currentUser();
       if(id != null && !id.equals("")){
           List<Topology> topologies = selectObjById(user, id, null);
           if(topologies != null && topologies.size() > 0){
               Map params = new HashMap();
               Topology topology = this.topologyService.selectObjById(id);
               params.put("topologyId", topology.getId());
               List<PresetPath> presetPaths = this.presetPathService.selectObjByMap(params);
               return ResponseUtil.ok(presetPaths);
           }
           return ResponseUtil.badArgument();
       }
        return ResponseUtil.ok();
    }

    public void setTopologyDefualt(){
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
            List<Topology> topologies = this.topologyService.selectObjByMap(params);
            if(topologies.size() == 1){
                Topology topology = topologies.get(0);
                topology.setIsDefault(true);
                this.topologyService.update(topology);
            }
        }
    }

    public  List<Topology> topologyList(User user){
        Map params = new HashMap();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
            List<Topology> topologies = this.topologyService.selectObjByMap(params);
            return topologies;
        }
        return null;
    }

    public  List<Topology> defaultList(User user, boolean isDefault){
        Map params = new HashMap();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            params.put("groupIds", ids);
            params.put("isDefault", true);
            List<Topology> topologies = this.topologyService.selectObjByMap(params);
            return topologies;
        }
        return null;
    }

    public  List<Topology> selectObjById(User user, Long id, Date time){
        Map params = new HashMap();
        Group group = this.groupService.selectObjById(user.getGroupId());
        if(group != null) {
            Set<Long> ids = this.groupTools.genericGroupId(group.getId());
            List<Topology> topologies = null;
            params.put("groupIds", ids);
            params.put("id", id);
            if(time == null){
                topologies = this.topologyService.selectObjByMap(params);
            }else{
                params.put("time", time);
                topologies = this.topologyHistoryService.selectObjByMap(params);
            }
            return topologies;
        }
        return null;
    }

//    @ApiOperation("设备路由列表")
//    @PostMapping("/device/rout")
//    public Object deviceRoutList(@RequestBody RoutDTO dto){
//        if(StringUtil.isEmpty(dto.getDeviceUuid())){
//            return ResponseUtil.badArgument();
//        }else{
//            if(dto.getDestination() != null && !dto.getDestination().equals("")){
//                dto.setDestination(IpUtil.ipConvertDec(dto.getDestination()));
//            }
//        }
//        Page<Route> page = null;
//        if(dto.getTime() == null){
//            page = this.routService.selectConditionQuery(dto);
//        }else{
//            page = this.routHistoryService.selectConditionQuery(dto);
//        }
//        if(page != null && page.getResult().size() > 0) {
//            return ResponseUtil.ok(new PageInfo<Route>(page));
//        }
//        return ResponseUtil.ok();
//    }

    @ApiOperation("设备路由列表")
    @PostMapping("/device/rout")
    public Object deviceRoutList(@RequestBody RoutDTO dto){
        NetworkElement networkElement = null;
        String ip = "";
        Integer maskBit = 0;
        if(StringUtil.isEmpty(dto.getDeviceUuid())){
            return ResponseUtil.badArgument("请选择设备");
        }else{
            networkElement = this.networkElementService.selectObjByUuid(dto.getDeviceUuid());
            if(networkElement == null){
                return ResponseUtil.badArgument("设备不存在");
            }
            String destination = dto.getDestination();
            if(destination != null && !destination.equals("")){
                boolean cidr = IpV4Util.verifyCidr(destination);
                if(cidr){
                    maskBit = Integer.parseInt(destination.replaceAll(".*/",""));
                    ip = destination.replaceAll("/.*","");
                    dto.setDestination(ip);
                }else{
                    boolean flag = IpV4Util.verifyIp(destination);
                    if(flag){
                        ip = destination;
                        maskBit = 32;
                    }else{
                        return ResponseUtil.badArgument();
                    }
                }
                dto.setDestination(IpUtil.ipConvertDec(dto.getDestination()));
            }
        }
        Page<Route> page = null;
        dto.setOrderBy("destination");
        dto.setOrderType("asc");
        if(dto.getTime() == null){
            page = this.routService.selectConditionQuery(dto);
        }else{
            page = this.routHistoryService.selectConditionQuery(dto);
        }
        if(page != null && page.getResult().size() > 0) {
            return ResponseUtil.ok(new PageInfo<Route>(page));
        }
            else {
            // 根据Ip未查询到数据（查询相同网段ip地址）
//            String mask = IpV4Util.getMaskByMaskBit(maskBit);
//            String network = IpV4Util.getNetwork(ip, mask);
//            String broadcast = IpV4Util.getBroadcast(ip, mask);
//            if(!StringUtil.isEmpty(network) && !StringUtils.isEmpty(broadcast)){
//                dto.setNetwork(network);
//                dto.setBroadcast(broadcast);
//                page = this.routService.selectConditionQuery(dto);
//                return ResponseUtil.ok(new PageInfo<Route>(page));
//            }
            dto.setDestination(null);
            page = this.routService.selectConditionQuery(dto);
            List<Route> routes = page.getResult();
            if(routes.size() > 0){
                List<Route> routList = new ArrayList<>();
                for (Route rout : routes) {
                    boolean flag = IpUtil.ipIsInNet(ip, rout.getCidr());
                    if (flag) {
                        routList.add(rout);
                    }
                }

                if(routList.size() > 0){
                    this.sort(routList);
                    int maskBitMax = routList.get(0).getMaskBit();
                    List<Route> routList2 = new ArrayList<>();
                    for (Route rout : routList) {
                        if (rout.getMaskBit() == maskBitMax) {
                            routList2.add(rout);
                        }
                    }
                    Page<Route> page1 = new Page<>();
                    page1.setPageNum(1);
                    page1.setPageSize(routList2.size());
                    page1.setPageSize(routList2.size());
                    page1.getResult().clear();
                    page1.getResult().addAll(routList2);
                    return ResponseUtil.ok(new PageInfo<Route>(page1));
                }else{
                    dto.setDestination("0");
                    page = this.routService.selectConditionQuery(dto);
                    return ResponseUtil.ok(new PageInfo<Route>(page));
                }
            }
            return ResponseUtil.ok();
        }
    }

    public static void sort(List<Route> list){
        Collections.sort(list, new Comparator<Route>() {
            @Override
            public int compare(Route o1, Route o2) {
                int key1 = o1.getMaskBit();
                int key2 = o2.getMaskBit();
                return key1 < key2 ? 1 : -1; // 降序
            }
        });
    }

    @ApiOperation("设备路由列表（历史）")
    @PostMapping("/device/rout/history")
    public Object deviceRoutListHistory(@RequestBody RoutDTO dto){
        if(StringUtil.isEmpty(dto.getDeviceUuid())){
            return ResponseUtil.badArgument();
        }else{
            if(dto.getDestination() != null && !dto.getDestination().equals("")){
                dto.setDestination(IpUtil.ipConvertDec(dto.getDestination()));
            }
        }
        Page<Route> page = null;
        page = this.routHistoryService.selectConditionQuery(dto);
        if(page != null && page.getResult().size() > 0) {
            return ResponseUtil.ok(new PageInfo<Route>(page));
        }
        return ResponseUtil.ok();
    }

    @RequestMapping("/upload")
    public Object upload(
                       @RequestParam(value = "file", required = false) MultipartFile file){
        if(file != null && file.getSize() > 0){
            boolean accessory = this.uploadFile(file);
            if(accessory){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

    public boolean uploadFile(@RequestParam(required = false) MultipartFile file){
        String path = "C:\\Users\\46075\\Desktop\\新建文件夹";
        String originalName = file.getOriginalFilename();
        String fileName = UUID.randomUUID().toString().replace("-", "");
        String ext = originalName.substring(originalName.lastIndexOf("."));
        String picNewName = fileName + ext;
        String imgRealPath = path  + File.separator + picNewName;
        Date currentDate = new Date();
        String fileName1 = DateTools.getCurrentDate(currentDate);
        System.out.println(path + "\\" + fileName1 + ".conf");
        java.io.File imageFile = new File(path +  "\\" + fileName1 + ".conf");
        if (!imageFile.getParentFile().exists()) {
            imageFile.getParentFile().mkdirs();
        }
        try {
            file.transferTo(imageFile);
            Accessory accessory = new Accessory();
            accessory.setA_name(picNewName);
            accessory.setA_path(path);
            accessory.setA_ext(ext);
            accessory.setA_size((int)file.getSize());
            accessory.setType(3);
            this.accessoryService.save(accessory);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    @GetMapping("/down")
    public Object down(HttpServletResponse response){
        String path = "C:\\Users\\46075\\Desktop\\新建文件夹\\20221017122442.conf";
        if(path != null && !path.equals("")){
            File file = new File(path);
            if(file != null){
                DownLoadFileUtil.downloadZip(file, response);
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

//    @ApiOperation("二层设备查询")
//    @RequestMapping("/layer_2_device")
//    public Object routTable(String srcIp, Integer srcMask, String destIp, Integer destMask){
//        if(StringUtil.isEmpty(srcIp)){
//            return ResponseUtil.badArgument("起点Ip不能为空");
//        }
//        if(!IpUtil.verifyIp(srcIp)){
//            return ResponseUtil.badArgument("起点Ip格式错误");
//        }
//        Arp srcArp = this.arpService.selectObjByIp(IpUtil.ipConvertDec(srcIp));
//        if(srcArp == null){
//            return ResponseUtil.badArgument("起点Ip不存在");
//        }
//        if(StringUtil.isEmpty(destIp)){
//            return ResponseUtil.badArgument("终点Ip不能为空");
//        }
//        if(!IpUtil.verifyIp(destIp)){
//            return ResponseUtil.badArgument("终点Ip格式错误");
//        }
//        Map map = new HashMap();
//        Arp destArp = this.arpService.selectObjByIp(IpUtil.ipConvertDec(destIp));
//        if(destArp == null){
//            return ResponseUtil.badArgument("终点Ip不存在");
//        }
//        Map params = new HashMap();
//        // 获取起点ip网络地址和广播地址
//        Map origin =  null;
//        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
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
//            this.routTableService.truncateTable();
//            // 保存起点设备
//            params.clear();
//            params.put("ip", srcIpAddress.getIp());
//            params.put("mask", srcIpAddress.getMask());
//            params.put("deviceName", srcIpAddress.getDeviceName());
//            params.put("interfaceName", srcIpAddress.getInterfaceName());
//            params.put("mac", srcIpAddress.getMac());
//            List<RouteTable> routTables = this.routTableService.selectObjByMap(params);
//            RouteTable routTable = null;
//            if(routTables.size() > 0){
//                routTable = routTables.get(0);
//            }else{
//                routTable = new RouteTable();
//            }
//            String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
//            BeanUtils.copyProperties(srcIpAddress, routTable, IGNORE_ISOLATOR_PROPERTIES);
//            this.routTableService.save(routTable);
//
//            // 路由查询
//            this.routTool.generatorRout(srcIpAddress, destIp, destIpAddress.getMask());
//            List<RouteTable> routTableList = this.routTableService.selectObjByMap(null);
//            map.put("routTable", routTableList);
//            // 二层路径
//            if(true){
//                // 起点二层路径
//                List<Mac> src_layer_2_device = this.routTool.generetorSrcLayer_2_device(srcArp.getMac(), srcIpAddress.getDeviceName());
//                int number = src_layer_2_device.size();
//                boolean flag = true;
//                if(number == 1){
//                    Mac mac = src_layer_2_device.get(0);
//                    if(mac.getTag().equals("L")){
//                        flag = false;
//                    }
//                }
//                if(number > 1 && flag){
//                    flag = false;
//                    map.put("src_layer_2_device", src_layer_2_device);
//                    map.put("srcRemoteDevice", new ArrayList<>());
//                }
//                if(flag){
//                    // 查找 二层路径 路由起点设备的remote设备为有起点ip的mac地址记录且与起点设备相连的那台设备
//                    params.clear();
//                    params.put("mac", srcArp.getMac());
//                    List<Mac> srcRemoteDevice = this.macService.selectByMap(params);
//                    if(srcRemoteDevice.size() > 0){
//                        Mac mac = srcRemoteDevice.get(0);
//                        params.clear();
//                        params.put("deviceName", mac.getDeviceName());
//                        List<Mac> macs = this.macService.selectByMap(params);
//                        map.put("srcRemoteDevice", new ArrayList<>());
//                        map.put("src_layer_2_device", new ArrayList<>());
//                        for(Mac obj : macs){
//                            if(obj.getRemoteDevice() != null && srcIpAddress.getDeviceName() != null){
//                                if(obj.getRemoteDevice().equals(srcIpAddress.getDeviceName())){
//                                    map.put("srcRemoteDevice", obj);
//                                    break;
//                                }
//                            }
//                        }
//                    }
//                }
//
//                // 查询终点二层路径
//                if(routTableList.size() > 0){
//                    List<RouteTable> destToutTables = routTableList.stream().filter(item -> item.getStatus() == 1 || item.getStatus() == 3).collect(Collectors.toList());
//                    Map routTableMap = new HashMap();
//                    List list = new ArrayList();
//                    List destRemoteList = new ArrayList();
//                    for(RouteTable item : destToutTables){
//                        List<Mac> dest_layer_2_device = this.routTool.generetorSrcLayer_2_device(destArp.getMac(), item.getDeviceName());
//                        int number1 = dest_layer_2_device.size();
//                        boolean flag1 = true;
//                        if(number1 == 1){
//                            Mac mac = dest_layer_2_device.get(0);
//                            if(mac.getTag().equals("L")){
//                                flag1 = false;
//                            }
//                        }
//                        if(number1 > 1 && flag1){
//                            flag1 = false;
//                            routTableMap.put(item.getIp(), dest_layer_2_device);
//                            list.add(dest_layer_2_device);
//                        }
//                        if(flag1){
//                            // 查找 二层路径 路由起点设备的remote设备为有起点ip的mac地址记录且与起点设备相连的那台设备
//                            params.clear();
//                            params.put("mac", destArp.getMac());
//                            List<Mac> destRemoteDevice = this.macService.selectByMap(params);
//                            if(destRemoteDevice.size() > 0){
//                                params.clear();
//                                params.put("remoteDevice", destIpAddress.getDeviceName());
//                                List<Mac> mac = this.macService.selectByMap(params);
//                                for(Mac obj : mac){
//                                    if(obj.getRemoteDevice() != null && destIpAddress.getDeviceName() != null){
//                                        if(obj.getRemoteDevice().equals(destIpAddress.getDeviceName())){
//                                            destRemoteList.add(obj);
//                                            break;
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                    map.put("dest_layer_2_device", list);
//                    map.put("destRemoteDevice", destRemoteList);
//                }
//            }
//            return ResponseUtil.ok(map);
//    }

    @ApiOperation("二层设备查询")
    @RequestMapping("/layer_2_device")
    public Object routTable(String srcIp, Integer srcMask, String destIp, Integer destMask,
                            @RequestParam(value = "time", required = false)
                            @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss") Date time,
                            @RequestParam(value = "type", defaultValue = "0") Integer type){
        if(StringUtil.isEmpty(srcIp)){
            return ResponseUtil.badArgument("起点Ip不能为空");
        }
        if(!IpUtil.verifyIp(srcIp)){
            return ResponseUtil.badArgument("起点Ip格式错误");
        }
        Arp srcArp = null;
        if(type == 1){
            srcArp = this.queryArp(srcIp, time);
            if(srcArp == null){
                return ResponseUtil.badArgument("起点Ip不存在");
            }
        }
        if(StringUtil.isEmpty(destIp)){
            return ResponseUtil.badArgument("终点Ip不能为空");
        }
        if(!IpUtil.verifyIp(destIp)){
            return ResponseUtil.badArgument("终点Ip格式错误");
        }
        Arp destArp = null;
        if(type == 1){
            destArp = this.queryArp(destIp, time);
            if(destArp == null){
                return ResponseUtil.badArgument("终点Ip不存在");
            }
        }
        // 查询路由
        Map map = new HashMap();
        Map params = new HashMap();
        // 获取起点ip网络地址和广播地址
        Map originMap =  null;
        List<Subnet> subnets = this.zabbixSubnetService.selectSubnetByParentId(null);
        if(subnets.size() > 0){
            if(srcIp != null){
                if(srcIp.equals("0.0.0.0")){
                }
                if(!IpUtil.verifyIp(srcIp)){
                }
                // 判断ip地址是否属于子网
                for(Subnet subnet : subnets){
                    Subnet sub = this.subnetTool.verifySubnetByIp(subnet, srcIp);
                    if(sub != null){
                        String mask = IpUtil.bitMaskConvertMask(sub.getMask());
                        originMap = IpUtil.getNetworkIpDec(sub.getIp(), mask);
                        break;
                    }
                }
            }
        }
        if(originMap == null || originMap.isEmpty()){
            return ResponseUtil.badArgument("起点Ip不存在");
        }
        IpAddress srcIpAddress = null;// 查询起点设备
        if(time == null){
            srcIpAddress = this.ipAddressServie.querySrcDevice(originMap);
        }else{
            originMap.put("time", time);
            srcIpAddress = this.ipAddressHistoryServie.querySrcDevice(originMap);
        }
        if(srcIpAddress == null){
            return ResponseUtil.badArgument("起点Ip不存在");
        }
        Map destMap = null;
        // 获取终点ip网络地址和广播地址
        if(subnets.size() > 0){
            if(destIp != null){
                if(destIp.equals("0.0.0.0")){
                }
                if(!IpUtil.verifyIp(destIp)){
                }
                // 判断ip地址是否属于子网
                for(Subnet subnet : subnets){
                    Subnet sub = this.subnetTool.verifySubnetByIp(subnet, destIp);
                    if(sub != null){
                        String mask = IpUtil.bitMaskConvertMask(sub.getMask());
                        destMap = IpUtil.getNetworkIpDec(sub.getIp(), mask);
                        break;
                    }
                }
            }
        }
        if(destMap == null || destMap.isEmpty()){
            return ResponseUtil.badArgument("终点Ip不存在");
        }
        // 终点设备
        IpAddress destIpAddress = null;
        if(time == null){
            destIpAddress = this.ipAddressServie.querySrcDevice(destMap);
        }else{
            destMap.put("time", time);
            destIpAddress = this.ipAddressHistoryServie.querySrcDevice(destMap);
        }
        if(destIpAddress == null){
            return ResponseUtil.badArgument("终点Ip不存在");
        }
        map.put("destinationDevice", destIpAddress);

        this.routTableService.truncateTable();// 清除 routTable

        // 保存起点设备到路由表
        params.clear();
        params.put("ip", srcIpAddress.getIp());
        params.put("mask", srcIpAddress.getMask());
        params.put("deviceName", srcIpAddress.getDeviceName());
        params.put("interfaceName", srcIpAddress.getInterfaceName());
        params.put("mac", srcIpAddress.getMac());
        List<RouteTable> routTables = this.routTableService.selectObjByMap(params);
        RouteTable routTable = null;
        if(routTables.size() > 0){
            routTable = routTables.get(0);
        }else{
            routTable = new RouteTable();
        }
        String[] IGNORE_ISOLATOR_PROPERTIES = new String[]{"id"};
        BeanUtils.copyProperties(srcIpAddress, routTable, IGNORE_ISOLATOR_PROPERTIES);
        this.routTableService.save(routTable);

        // 路由查询
        this.routTool.generatorRout(srcIpAddress, destIp, destIpAddress.getMask(), time);
        List<RouteTable> routTableList = this.routTableService.selectObjByMap(null);
        map.put("routTable", routTableList);

        // 二层路径
        if(type == 1){
            // 起点二层路径
            List<Mac> src_layer_2_device = this.routTool.generetorSrcLayer_2_device(srcArp.getMac(), srcIpAddress.getDeviceName(), time);
            int number = src_layer_2_device.size();
            boolean flag = true;
            if(number == 1){
                Mac mac = src_layer_2_device.get(0);
                if(mac.getTag().equals("L")){
                    flag = false;
                }
            }
            if(number > 1 && flag){
                flag = false;
                map.put("src_layer_2_device", src_layer_2_device);
                map.put("srcRemoteDevice", new ArrayList<>());
            }
            if(flag){
                // 查找 二层路径 路由起点设备的remote设备为有起点ip的mac地址记录且与起点设备相连的那台设备
                params.clear();
                params.put("mac", srcArp.getMac());
                List<Mac> srcRemoteDevice = this.routTool.queryMac(params, time);
//                List<Mac> srcRemoteDevice = this.macService.selectByMap(params);
                if(srcRemoteDevice.size() > 0){
                    Mac mac = srcRemoteDevice.get(0);
                    params.clear();
                    params.put("deviceName", mac.getDeviceName());
                    List<Mac> macs = this.routTool.queryMac(params, time);
//                    List<Mac> macs = this.macService.selectByMap(params);
                    map.put("srcRemoteDevice", new ArrayList<>());
                    map.put("src_layer_2_device", new ArrayList<>());
                    for(Mac obj : macs){
                        if(obj.getRemoteDevice() != null && srcIpAddress.getDeviceName() != null){
                            if(obj.getRemoteDevice().equals(srcIpAddress.getDeviceName())){
                                map.put("srcRemoteDevice", obj);
                                break;
                            }
                        }
                    }
                }
            }

            // 查询终点二层路径
            if(routTableList.size() > 0){
                List<RouteTable> destToutTables = routTableList.stream().filter(item -> item.getStatus() == 1 || item.getStatus() == 3).collect(Collectors.toList());
                Map routTableMap = new HashMap();
                List list = new ArrayList();
                List destRemoteList = new ArrayList();
                for(RouteTable item : destToutTables){
                    List<Mac> dest_layer_2_device = this.routTool.generetorSrcLayer_2_device(destArp.getMac(), item.getDeviceName(), time);
                    int number1 = dest_layer_2_device.size();
                    boolean flag1 = true;
                    if(number1 == 1){
                        Mac mac = dest_layer_2_device.get(0);
                        if(mac.getTag().equals("L")){
                            flag1 = false;
                        }
                    }
                    if(number1 > 1 && flag1){
                        flag1 = false;
                        routTableMap.put(item.getIp(), dest_layer_2_device);
                        list.add(dest_layer_2_device);
                    }
                    if(flag1){
                        // 查找 二层路径 路由起点设备的remote设备为有起点ip的mac地址记录且与起点设备相连的那台设备
                        params.clear();
                        params.put("mac", destArp.getMac());
                        List<Mac> destRemoteDevice = this.routTool.queryMac(params, time);
//                        List<Mac> destRemoteDevice = this.macService.selectByMap(params);
                        if(destRemoteDevice.size() > 0){
                            params.clear();
                            params.put("remoteDevice", destIpAddress.getDeviceName());
                            List<Mac> mac = this.routTool.queryMac(params, time);
//                            List<Mac> mac = this.macService.selectByMap(params);
                            for(Mac obj : mac){
                                if(obj.getRemoteDevice() != null && destIpAddress.getDeviceName() != null){
                                    if(obj.getRemoteDevice().equals(destIpAddress.getDeviceName())){
                                        destRemoteList.add(obj);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                map.put("dest_layer_2_device", list);
                map.put("destRemoteDevice", destRemoteList);
            }
        }
        return ResponseUtil.ok(map);
    }

    public Arp queryArp(String ip, Date time){
        Arp arp = null;
        if(time == null){
            arp = this.arpService.selectObjByIp(IpUtil.ipConvertDec(ip));
        }else {
            Map params = new HashMap();
            params.clear();
            params.put("ip", IpUtil.ipConvertDec(ip));
            params.put("time", time);
            List<Arp> srcArps = this.arpHistoryService.selectObjByMap(params);
            if (srcArps.size() > 0) {
                arp = srcArps.get(0);
            }
        }
        return arp;
    }

}
