package com.metoo.nspm.core.manager.admin.action;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.util.StringUtil;
import com.metoo.nspm.core.manager.admin.tools.DateTools;
import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostService;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.service.zabbix.InterfaceService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.file.DownLoadFileUtil;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.poi.ExcelUtil;
import com.metoo.nspm.core.utils.poi.ExcelUtils;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.DeviceConfigDTO;
import com.metoo.nspm.dto.NetworkElementDto;
import com.github.pagehelper.Page;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.entity.zabbix.Interface;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.shiro.crypto.hash.Hash;
import org.aspectj.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.Response;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;

@Api("网元管理")
@RequestMapping("/nspm/ne")
@RestController
public class NetworkElementManagerController {

    @Autowired
    private INetworkElementService networkElementService;
    @Autowired
    private IRsmsDeviceService rsmsDeviceService;
    @Autowired
    private IDeviceTypeService deviceTypeService;
    @Autowired
    private IVendorService vendorService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private GroupTools groupTools;
    @Autowired
    private ZabbixHostService zabbixHostService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private IDeviceConfigService deviceConfigService;
    @Autowired
    private InterfaceService interfaceService;
    @Autowired
    private ITopologyService topologyService;
    @Autowired
    private ICredentialService credentialService;

    @Value("${batchImportNeFileName}")
    private String batchImportNeFileName;
    @Value("${batchImportFilePath}")
    private String batchImportFilePath;


    public static void main(String[] args) {
        String path = "C:\\software\\VP";
        File file = new File(path);
        if(!file.exists()){
            System.out.println(true);
        }else{
            System.out.println(false);
        }
    }

    @RequestMapping("/list")
    public Object list(@RequestBody(required=false) NetworkElementDto dto){
        if(dto == null){
            dto = new NetworkElementDto();
        }
        User user = ShiroUserHolder.currentUser();
//        dto.setUserId(user.getId()); 相同分组下，网元可见
        if(dto.getGroupId() != null){
            Group group = this.groupService.selectObjById(dto.getGroupId());
            if(group != null){
                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                dto.setGroupIds(ids);
            }
        }
        Page<NetworkElement> page = this.networkElementService.selectConditionQuery(dto);
        if(page.getResult().size() > 0){
            // 获取主机状态
            for(NetworkElement ne : page.getResult()){
                if(ne.getIp() != null){
                    Interface obj = this.interfaceService.selectObjByIp(ne.getIp());
                    if(obj != null){
                        ne.setAvailable(obj.getAvailable());
                        ne.setError(obj.getError());
                    }
                }
                if(ne.getCredentialId() != null){
                    Credential credential = this.credentialService.getObjById(ne.getCredentialId());
                    if(credential != null){
                        ne.setCredentialName(credential.getName());
                    }
                }
            }

            return ResponseUtil.ok(new PageInfo<NetworkElement>(page));
//            ExecutorService exe = Executors.newFixedThreadPool(page.getResult().size());
//            for(NetworkElement ne : page.getResult()){
//                if(ne.getIp() != null){
//                    exe.execute(new Thread(new Runnable() {
//                        @Override
//                        public void run() {
//                            try {
//                                JSONObject hostInterface = zabbixHostInterfaceService.getHostInterfaceInfo(ne.getIp());
//                                if(hostInterface != null){
//                                    ne.setAvailable(hostInterface.getString("available"));
//                                    ne.setError(hostInterface.getString("error"));
//                                }
//                            } catch (Exception e) {
//                                e.printStackTrace();
//                            }
//                        }
//                    }));
//                }
//            }
//            exe.shutdown();
//            while (true) {
//                if (exe.isTerminated()) {
//                    return ResponseUtil.ok(new PageInfo<NetworkElement>(page));
//                }
//            }
        }
        return  ResponseUtil.ok();
    }

    @GetMapping("/all")
    public Object all(){
        List<NetworkElement> networkElements = this.networkElementService.selectObjAll();
        return ResponseUtil.ok(networkElements);
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
        // 厂商
        List<Vendor> vendors = this.vendorService.selectConditionQuery(null);
        map.put("vendor", vendors);
        // 设备类型
//        Map params = new HashMap();
//        params.put("types", Arrays.asList(0,1,2,5));
//        List<DeviceType> deviceTypeList = this.deviceTypeService.selectObjByMap(params);
//        map.put("device", deviceTypeList);
        List<DeviceType> deviceTypeList = this.deviceTypeService.selectConditionQuery();
        map.put("device", deviceTypeList);
        // 凭据列表
        List<Credential> credentials = this.credentialService.getAll();
        map.put("credential", credentials);
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
        map.put("group", groupList);
        // 设备类型
        Map params = new HashMap();
//        params.put("types", Arrays.asList(0,1,2,5));
        List<DeviceType> deviceTypeList = this.deviceTypeService.selectObjByMap(params);
        map.put("device", deviceTypeList);
        // 厂商
        List<Vendor> vendors = this.vendorService.selectConditionQuery(null);
        map.put("vendor", vendors);
        NetworkElement networkElement = this.networkElementService.selectObjById(id);
        map.put("networkElement", networkElement);
        // 凭据列表
        List<Credential> credentials = this.credentialService.getAll();
        map.put("credential", credentials);
        return ResponseUtil.ok(map);
    }

    @PostMapping("/save")
    public Object save(@RequestBody(required=false) NetworkElement instance){
        // 验证Ip唯一性
//        if(instance.getIp() == null || instance.getIp().equals("")){
//            return ResponseUtil.badArgument("请输入有效IP");
//        }else{
//            // 验证ip合法性
//            boolean flag =  IpUtil.verifyIp(instance.getIp());
//            if(!flag){
//                return ResponseUtil.badArgument("ip不合法");
//            }
//            Map params = new HashMap();
//            params.put("neId", instance.getId());
//            params.put("ip", instance.getIp());
//            List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
//            if(nes.size() > 0){
//                return ResponseUtil.badArgument("IP重复");
//            }
//        }
        String name = "";
        String newName = "";
        String ip = "";
        String newIp = "";
        String deviceTypeName = "";
        NetworkElement ne = null;
        if(instance.getId() != null){
            ne = this.networkElementService.selectObjById(instance.getId());
            if(ne.getDeviceName() != instance.getDeviceName()){
                name = ne.getDeviceName();
                newName = instance.getDeviceName();
            }
            if(ne.getIp() != instance.getIp()){
                ip = ne.getIp();
                newIp = instance.getIp();
            }
        }
        if (instance.getIp() != null || !instance.getIp().equals("")) {
            // 验证ip合法性
            boolean flag =  IpUtil.verifyIp(instance.getIp());
            if(!flag){
                return ResponseUtil.badArgument("ip不合法");
            }
            Map params = new HashMap();
            params.put("neId", instance.getId());
            params.put("ip", instance.getIp());
            List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
            if(nes.size() > 0){
                return ResponseUtil.badArgument("IP重复");
            }
        }
        // 验证设备名唯一性
        Map params = new HashMap();
        if(instance.getDeviceName() == null || instance.getDeviceName().equals("")){
            return ResponseUtil.badArgument("设备名不能为空");
        }else {
            params.clear();
            params.put("neId", instance.getId());
            params.put("deviceName", instance.getDeviceName());
            List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
            if (nes.size() > 0) {
                return ResponseUtil.badArgument("设备名称重复");
            }
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
        // 验证设备类型是否存在
        DeviceType deviceType = this.deviceTypeService.selectObjById(instance.getDeviceTypeId());
        if(deviceType == null){
            return ResponseUtil.badArgument("设备类型不存在");
        }else{
            instance.setDeviceTypeName(deviceType.getName());
            if(deviceType.getType() == 10){
                instance.setInterfaceName("Port0");
            }

            if(ne != null && !ne.getDeviceTypeName().equals(deviceType.getName())){
                deviceTypeName = deviceType.getName();
            }
        }
        // 验证厂商
        Vendor vendor = this.vendorService.selectObjById(instance.getVendorId());
        if(vendor != null){
            instance.setVendorName(vendor.getName());
        }

        // 验证是否允许远程连接
        if(instance.isPermitConnect()){
            if(instance.getPort() == null || instance.getPort().equals("")){
                return ResponseUtil.badArgument("端口不能为空");
            }
            if(instance.getCredentialId() == null || instance.getCredentialId().equals("")){
                return ResponseUtil.badArgument("请选择凭据");
            }
            // 验证是否选择凭据
            Credential credential = this.credentialService.getObjById(instance.getCredentialId());
            if(credential == null){
                return ResponseUtil.badArgument("凭据不存在");
            }
        }else{
            instance.setCredentialId(null);
        }

        if(this.networkElementService.save(instance) >= 1 ? true : false){
            // 同步拓扑
            if(!name.equals("") || ip.equals("")){
                this.updateTopology("update", name, ip, newName, newIp, deviceTypeName);
            }

            // 同步设备信息
            // 验证名称是否唯一
            if(instance.isSync_device() && instance.getDeviceName() != null && !instance.getDeviceName().isEmpty()){
                params.clear();
                params.put("id", instance.getId());
                params.put("name", instance.getDeviceName());
                List<RsmsDevice> rsmsDeviceList = this.rsmsDeviceService.selectObjByMap(params);
                if(rsmsDeviceList.size() > 0){
                    return ResponseUtil.ok("添加成功【设备同步失败：设备已存在】");
                }else{
                    try {
                        RsmsDevice rsmsDevice = new RsmsDevice();// copy
                        rsmsDevice.setIp(instance.getIp());
                        rsmsDevice.setName(instance.getDeviceName());
                        rsmsDevice.setDeviceTypeId(instance.getDeviceTypeId());
                        rsmsDevice.setDeviceTypeName(instance.getDeviceTypeName());
                        rsmsDevice.setVendorId(instance.getVendorId());
                        rsmsDevice.setVendorName(instance.getVendorName());
                        rsmsDevice.setGroupId(instance.getGroupId());
                        rsmsDevice.setGroupName(instance.getGroupName());
                        rsmsDevice.setDescription(instance.getDescription());
                        rsmsDevice.setUuid(instance.getUuid());
                        this.rsmsDeviceService.save(rsmsDevice);
                        return ResponseUtil.ok("添加成功【设备同步成功】");
                    } catch (Exception e) {
                        e.printStackTrace();
                        return ResponseUtil.ok("添加成功【设备同步失败】");
                    }
                }
            }
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.badArgument();
        }
    }
//
//    @RequestMapping("/updateTopology")
    @Async
    public void updateTopology(String type, String name, String ip, String newName, String newIp, String deviceType){
        List<Topology> topologies = this.topologyService.selectObjByMap(null);
        if(topologies.size() > 0){
            for (Topology topology : topologies) {
                boolean flag = false;
                if(topology.getContent() != null){
                    Map content = JSONObject.parseObject(topology.getContent().toString(), Map.class);
                    if(content.get("layout") != null){
                        JSONArray layouts = JSONArray.parseArray(content.get("layout").toString());
                        List list = new ArrayList();
                        if(layouts.size() > 0){
                            for (Object object : layouts) {
                                Map layout = JSONObject.parseObject(object.toString(), Map.class);
                                if(layout.get("type") != null
                                        && layout.get("type").equals("device")
                                        && layout.get("nodeMessage") != null){
                                    Map nodeMessage = JSONObject.parseObject(layout.get("nodeMessage").toString(), Map.class);
                                    if(nodeMessage.get("ip").equals(ip)
                                            && nodeMessage.get("name").equals(name)){
                                        if(type.equals("update")){
                                            layout.put("text", newName);
                                            layout.put("nodeType", deviceType);
                                            nodeMessage.put("ip", newIp);
                                            nodeMessage.put("name", newName);
                                        }else if(type.equals("delete")){
                                            layout.put("status", -1);
                                        }
                                        flag = true;
                                        layout.put("nodeMessage", nodeMessage);
                                    }
                                    list.add(layout);
                                }else{
                                    list.add(layout);
                                }

                            }
                            content.put("layout", list);
                        }
                    }
                    if(content.get("links") != null){
                        JSONArray links = JSONArray.parseArray(content.get("links").toString());
                        List list = new ArrayList();
                        if(links.size() > 0) {
                            for (Object object : links) {
                                Map link = JSONObject.parseObject(object.toString(), Map.class);
                                if(link.get("fromNode") != null){
                                    Map fromNode = JSONObject.parseObject(link.get("fromNode").toString(), Map.class);
                                    if(fromNode.get("ip").equals(ip)
                                            && fromNode.get("name").equals(name)){
                                        fromNode.put("ip", newIp);
                                        fromNode.put("name", newName);
                                        link.put("fromNode", fromNode);
                                    }
                                }
                                if(link.get("toNode") != null){
                                    Map toNode = JSONObject.parseObject(link.get("toNode").toString(), Map.class);
                                    if(toNode.get("ip").equals(ip)
                                            && toNode.get("name").equals(name)){
                                        toNode.put("ip", newIp);
                                        toNode.put("name", newName);
                                        link.put("toNode", toNode);
                                    }
                                }
                                list.add(link);
                            }
                            content.put("links", list);
//                            String str = JSONObject.toJSONString(content);
//                            topology.setContent(str);
                        }
                    }
                    if(flag){
                        String str = JSONObject.toJSONString(content);
                        topology.setContent(str);
                        this.topologyService.update(topology);
                    }
                }

            }
        }

    }

    @DeleteMapping("/delete")
    public Object delete(String ids){
        if(ids != null && !ids.equals("")){
            User user = ShiroUserHolder.currentUser();
            for (String id : ids.split(",")){
                Map params = new HashMap();
                params.put("userId", user.getId());
                params.put("id", Long.parseLong(id));
                List<NetworkElement> nes = this.networkElementService.selectObjByMap(params);
                if(nes.size() > 0){
                    NetworkElement ne = nes.get(0);
                    try {
                        int i = this.networkElementService.del(Long.parseLong(id));
                        if(i >= 1){
                            try {
                                // 同步删除网元配置
                                this.zabbixHostService.deleteHost(ne.getIp());
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            this.updateTopology("delete", ne.getDeviceName(),
                                    ne.getIp(), "", "", "");
                        }
                    } catch (NumberFormatException e) {
                        e.printStackTrace();
                        return ResponseUtil.badArgument(ne.getDeviceName() + "删除失败");
                    }
                }else{
                    return ResponseUtil.badArgument();
                }
            }

            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument();
    }

    @PostMapping("/config/list")
    public Object configList(@RequestBody(required = true)DeviceConfigDTO dto){
//        NetworkElement networkElement = this.networkElementService.selectObjById(dto.getNeId());
        NetworkElement networkElement = this.networkElementService.selectObjByUuid(dto.getNeUuid());
        if(networkElement != null){
            if(dto == null){
                dto = new DeviceConfigDTO();
            }
            Page<DeviceConfig> page = this.deviceConfigService.selectConditionQuery(dto);
            if(page.getResult().size() > 0){
//                for(DeviceConfig deviceConfig : page.getResult()){
//                    String data = this.info(deviceConfig.getId());
//                    deviceConfig.setData(data);
//                }
                return ResponseUtil.ok(new PageInfo<DeviceConfig>(page));
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.badArgument("请选择网元");
    }

    @RequestMapping("/config/upload")
    public Object uploadConfig(@RequestParam(value = "file", required = false) MultipartFile file, Long id){
        NetworkElement ne = this.networkElementService.selectObjById(id);
        if(ne != null){
            if(file != null){
                Accessory accessory = this.uploadFile(file);
                if(accessory != null){
                    DeviceConfig deviceConfig = new DeviceConfig();
                    deviceConfig.setAddTime(new Date());
                    deviceConfig.setName(accessory.getA_name());
                    deviceConfig.setNeId(ne.getId());
                    deviceConfig.setAccessoryId(accessory.getId());
                    deviceConfig.setNeUuid(ne.getUuid());
                    this.deviceConfigService.save(deviceConfig);
                    return ResponseUtil.ok();
                }else{
                    return ResponseUtil.error();
                }
            }
            return ResponseUtil.badArgument();
        }
        return ResponseUtil.badArgument();
    }

    @RequestMapping("/config/down")
    public Object uploadConfig(HttpServletResponse response, Long id){
       DeviceConfig deviceConfig = this.deviceConfigService.selectObjById(id);
       if(deviceConfig != null){
           NetworkElement networkElement = this.networkElementService.selectObjById(deviceConfig.getNeId());
           if(networkElement != null){
                Accessory accessory = this.accessoryService.getObjById(deviceConfig.getAccessoryId());
                if(accessory != null){
                    // 下载文件
//                    String path = "C:\\Users\\46075\\Desktop\\新建文件夹\\";
                    String path = accessory.getA_path() + "/" + accessory.getA_name() + accessory.getA_ext();
                    File file = new File(path);
                    if(file.exists()){
                        boolean flag = DownLoadFileUtil.downloadZip(file, response);
                        if(flag){
                            return ResponseUtil.ok();
                        }else{
                            return ResponseUtil.error();
                        }
                    }else{
                        return ResponseUtil.badArgument("文件不存在");
                    }
                }
               return ResponseUtil.badArgument("文件不存在");
           }
       }
       return ResponseUtil.badArgument();
    }

    public String info(Long id){
        DeviceConfig deviceConfig = this.deviceConfigService.selectObjById(id);
        if(deviceConfig != null){
            NetworkElement networkElement = this.networkElementService.selectObjById(deviceConfig.getNeId());
            if(networkElement != null){
                Accessory accessory = this.accessoryService.getObjById(deviceConfig.getAccessoryId());
                if(accessory != null){
                    // 读取文件
                    String path = accessory.getA_path() + "/" + accessory.getA_name() + accessory.getA_ext();
                    File file = new File(path);
                    if(file.exists()){
                        ByteArrayOutputStream bos = null;
                        BufferedInputStream bis = null;
                        try {
                            bos = new ByteArrayOutputStream();
                            bis = new BufferedInputStream(new FileInputStream(file));
                            byte[] bytes = new byte[1024];
                            int len = 0;
                            while ((len = bis.read(bytes)) > 0) {
                                bos.write(bytes,0,len);
                                bos.flush();
                            }
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        try {
                            bos.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        try {
                            bis.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        return bos.toString();
                    }
                }
            }
        }
        return "";
    }

    @GetMapping("/config/info")
    public Object info(@RequestParam(value = "ids") String ids){
        Map map = new HashMap();
        for(String id : ids.split(",")){
            DeviceConfig deviceConfig = this.deviceConfigService.selectObjById(Long.parseLong(id));
            if(deviceConfig != null){
                NetworkElement networkElement = this.networkElementService.selectObjById(deviceConfig.getNeId());
                if(networkElement != null){
                    Accessory accessory = this.accessoryService.getObjById(deviceConfig.getAccessoryId());
                    if(accessory != null){
                        // 读取文件
                        String path = accessory.getA_path() + "/" + accessory.getA_name() + accessory.getA_ext();
                        File file = new File(path);
                        if(file.exists()){
                            ByteArrayOutputStream bos = null;
                            BufferedInputStream bis = null;
                            try {
                                bos = new ByteArrayOutputStream();
                                bis = new BufferedInputStream(new FileInputStream(file));
                                byte[] bytes = new byte[1024];
                                int len = 0;
                                while ((len = bis.read(bytes)) > 0) {
                                    bos.write(bytes,0,len);
                                    bos.flush();
                                }
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            try {
                                bos.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            try {
                                bis.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            map.put(id, bos.toString()+" ");
                        }else{
                            map.put(id, "");
                        }
                    }
                }
            }
        }
        return ResponseUtil.ok(map);
    }

    public Accessory uploadFile(@RequestParam(required = false) MultipartFile file){
//        String path = "C:\\Users\\46075\\Desktop\\新建文件夹";
        try {
//            path = ClassUtils.getDefaultClassLoader().getResource("").getPath() + "static/topology";
//            path = ResourceUtils.getURL("classpath:").getPath() + "/static/topology/config";
//            String path = "/opt/topology/service/nspm/file";
            String path = "/opt/nmap/service/nmap/file";
//        String originalName = file.getOriginalFilename();
//        String fileName = UUID.randomUUID().toString().replace("-", "");
//        String ext = originalName.substring(originalName.lastIndexOf("."));
//        String picNewName = fileName + ext;
//        String imgRealPath = path  + File.separator + picNewName;
            Date currentDate = new Date();
            String fileName = DateTools.getCurrentDate(currentDate);
            String ext = ".conf";
            File folder = new File(URLDecoder.decode( path +  "/" + fileName + ext,"utf-8"));
            if(!folder.exists()){
                folder.mkdir();
            }
            file.transferTo(folder);
            Accessory accessory = new Accessory();
            accessory.setA_name(fileName);
            accessory.setA_path(URLDecoder.decode(path, "utf-8"));
            accessory.setA_ext(ext);
            accessory.setA_size((int)file.getSize());
            accessory.setType(3);
            this.accessoryService.save(accessory);
            return accessory;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }catch (FileNotFoundException e) {
                e.printStackTrace();
        }catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    @ApiOperation("Excel导入")
    @PostMapping("/import2")
    public Object importExcel2(@RequestPart("file")MultipartFile file) throws Exception {
        if(!file.isEmpty()){
            String fileName = file.getOriginalFilename().toLowerCase();
            String suffix = fileName.substring(fileName.lastIndexOf(".")+1).toLowerCase();
            if (suffix.equals("xlsx") || suffix.equals("xls")) {
                List<NetworkElement> nes = ExcelUtil.readMultipartFile(file, NetworkElement.class);
                if(nes.size() > 0){
                    String msg = "";
                    Map params = new HashMap();
                    List<NetworkElement> neList = new ArrayList<>();
                    for (int i = 0; i < nes.size(); i++) {
                        NetworkElement ne = nes.get(i);
                        if(ne.getDeviceName()  == null || ne.getDeviceName().equals("")){
                            msg = "第" + (i + 2) + "行,设备名不能为空";
                            break;
                        }else{
                            params.clear();
                            params.put("deviceName", ne.getDeviceName());
                            List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                            if(networkElements.size() > 0){
                                msg = "第" + (i + 2) + "行, 设备已存在";
                                break;
                            }
                        }
                        // 增加外联设备，ip必填校验删除
//                        if(ne.getIp()  == null || ne.getIp().equals("")){
//                            ne.setIp("");
//                            msg = "第" + (i + 2) + "行,IP不能为空";
//                            break;
//                        }
                        if(ne.getIp() != null && !ne.getIp().equals("")){
                            boolean flag = IpUtil.verifyIp(ne.getIp());
                            if(flag){
                                params.clear();
                                params.put("ip", ne.getIp());
                                List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                                if(networkElements.size() > 0){
                                    msg = "第" + (i + 2) + "行, IP已存在";
                                    break;
                                }
                            }else{
                                msg = "第" + (i + 2) + "行, IP格式错误";
                                break;
                            }
                        }
                        if(ne.getVendorName() != null ||ne.getVendorName().equals("")){
                            params.clear();
                            params.put("name", ne.getVendorName());
                            Vendor vendor = this.vendorService.selectObjByName(ne.getVendorName());
                            if(vendor == null){
                                msg = "第" + (i + 2) + "行,品牌不存在";
                                break;
                            }else{
                                ne.setVendorId(vendor.getId());
                            }
                        }
                        if(ne.getDeviceTypeName() != null || ne.getDeviceTypeName().equals("")){
                            params.clear();
                            params.put("name", ne.getDeviceTypeName());
                            DeviceType deviceType = this.deviceTypeService.selectObjByName(ne.getDeviceTypeName());
                            if(deviceType == null){
                                msg = "第" + (i + 2) + "行,设备类型不存在";
                                break;
                            }else{
                                ne.setDeviceTypeId(deviceType.getId());
                                if(deviceType.getType() == 10){
                                    ne.setInterfaceName("Port0");
                                }
                            }
                        }
                        neList.add(ne);
                    }
                    if(msg.isEmpty()){
                        // 批量插入NE
                        int i = this.networkElementService.batchInsert(neList);
                        if(i > 0){
                            return ResponseUtil.ok();
                        }else{
                            return ResponseUtil.error();
                        }
                    }else{
                        return ResponseUtil.badArgument(msg);
                    }
                }else{
                    return ResponseUtil.badArgument("文件无数据");
                }
            }else{
                return ResponseUtil.badArgument("文件格式错误，请使用标准模板上传");
            }
        }
        return ResponseUtil.badArgument("文件不存在");
    }


    @PostMapping("/import")
    public Object importExcel(@RequestPart("file")MultipartFile file) throws Exception {
        if(!file.isEmpty()){
            String fileName = file.getOriginalFilename().toLowerCase();
            String suffix = fileName.substring(fileName.lastIndexOf(".")+1).toLowerCase();
            if (suffix.equals("xlsx") || suffix.equals("xls")) {
                List<NetworkElement> nes = ExcelUtils.readMultipartFile(file, NetworkElement.class);
                // 校验表格数据是否符号要求
                String tips = "";
                for (NetworkElement ne : nes) {
                    if(!ne.getRowTips().isEmpty()){
                        tips = ne.getRowTips();
                        break;
                    }
                }
                if(!tips.isEmpty()){
                    return ResponseUtil.badArgument(tips);
                }
                if(nes.size() > 0){
                    String msg = "";
                    Map params = new HashMap();
                    List<NetworkElement> neList = new ArrayList<>();
                    for (int i = 0; i < nes.size(); i++) {
                        NetworkElement ne = nes.get(i);
                        if(ne.getDeviceName()  == null || ne.getDeviceName().equals("")){
                            msg = "第" + (i + 2) + "行,设备名不能为空";
                            break;
                        }else{
                            params.clear();
                            params.put("deviceName", ne.getDeviceName());
                            List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                            if(networkElements.size() > 0){
                                msg = "第" + (i + 2) + "行, 设备已存在";
                                break;
                            }
                        }
                        // 增加外联设备，ip必填校验删除
//                        if(ne.getIp()  == null || ne.getIp().equals("")){
//                            ne.setIp("");
//                            msg = "第" + (i + 2) + "行,IP不能为空";
//                            break;
//                        }
                        if(ne.getIp() != null && !ne.getIp().equals("")){
                            boolean flag = IpUtil.verifyIp(ne.getIp());
                            if(flag){
                                params.clear();
                                params.put("ip", ne.getIp());
                                List<NetworkElement> networkElements = this.networkElementService.selectObjByMap(params);
                                if(networkElements.size() > 0){
                                    msg = "第" + (i + 2) + "行, IP已存在";
                                    break;
                                }
                            }else{
                                msg = "第" + (i + 2) + "行, IP格式错误";
                                break;
                            }
                        }
                        if(ne.getVendorName() != null ||ne.getVendorName().equals("")){
                            params.clear();
                            params.put("name", ne.getVendorName());
                            Vendor vendor = this.vendorService.selectObjByName(ne.getVendorName());
                            if(vendor == null){
                                msg = "第" + (i + 2) + "行,品牌不存在";
                                break;
                            }else{
                                ne.setVendorId(vendor.getId());
                            }
                        }
                        if(ne.getDeviceTypeName() != null || ne.getDeviceTypeName().equals("")){
                            params.clear();
                            params.put("name", ne.getDeviceTypeName());
                            DeviceType deviceType = this.deviceTypeService.selectObjByName(ne.getDeviceTypeName());
                            if(deviceType == null){
                                msg = "第" + (i + 2) + "行,设备类型不存在";
                                break;
                            }else{
                                ne.setDeviceTypeId(deviceType.getId());
                                if(deviceType.getType() == 10){
                                    ne.setInterfaceName("Port0");
                                }
                            }
                        }
                        neList.add(ne);
                    }
                    if(msg.isEmpty()){
                        // 批量插入NE
                        int i = this.networkElementService.batchInsert(neList);
                        if(i > 0){
                            return ResponseUtil.ok();
                        }else{
                            return ResponseUtil.error();
                        }
                    }else{
                        return ResponseUtil.badArgument(msg);
                    }
                }else{
                    return ResponseUtil.badArgument("文件无数据");
                }
            }else{
                return ResponseUtil.badArgument("文件格式错误，请使用标准模板上传");
            }
        }
        return ResponseUtil.badArgument("文件不存在");
    }

    @ApiOperation("导出")
    @GetMapping("/device/export")
    public void exportExcel(HttpServletResponse response){
        List<NetworkElement> networkElements = new ArrayList<NetworkElement>();
        NetworkElement networkElement = new NetworkElement();
        networkElement.setDeviceName("test");
        networkElement.setIp("1.1.1.1");
        networkElement.setVendorName("vendor");
        networkElement.setDeviceTypeName("deviceType");
        networkElement.setDescription("desc");
        networkElements.add(networkElement);

        //时间
        long begin = System.currentTimeMillis();
        // 创建一个工作薄
        Workbook workbook = new HSSFWorkbook();
        // 创建一个工作表
        Sheet sheet = workbook.createSheet("设备信息");
        // 创建行 默认从0开始
        Row row1 = sheet.createRow(0);
        // 创建单元格 默认从0开始
        // （1,1）
        Cell cell1 = row1.createCell(0);
        cell1.setCellValue("序号");
        Cell cell2 = row1.createCell(1);
        cell2.setCellValue("设备名称");
        Cell cell3 = row1.createCell(2);
        cell3.setCellValue("管理地址");
        Cell cell4 = row1.createCell(3);
        cell4.setCellValue("厂商");
        Cell cell5 = row1.createCell(4);
        cell5.setCellValue("类型");
        Cell cell6 = row1.createCell(5);
        cell6.setCellValue("用途描述");
        Cell cell7 = row1.createCell(6);
        cell7.setCellValue("SNMP版本");
        Cell cell8 = row1.createCell(7);
        cell8.setCellValue("SNMP community");
        // 写入数据
        for (int rowNum = 1; rowNum <= networkElements.size(); rowNum++) {
            Row row = sheet.createRow(rowNum);
            NetworkElement obj = networkElements.get(rowNum - 1);
            Cell cell21 = row.createCell(0);
            cell21.setCellValue(rowNum);
            Cell cell22 = row.createCell(1);
            cell22.setCellValue(obj.getDeviceName());
            Cell cell23 = row.createCell(2);
            cell23.setCellValue(obj.getIp());
            Cell cell24 = row.createCell(3);
            cell24.setCellValue(obj.getVendorName());
            Cell cell25 = row.createCell(4);
            cell25.setCellValue(obj.getDeviceTypeName());
            Cell cell26 = row.createCell(5);
            cell26.setCellValue(obj.getDescription());
            Cell cell27 = row.createCell(6);
            cell27.setCellValue("V2");
            Cell cell28 = row.createCell(7);
            cell28.setCellValue("read");
        }

        //生成一张表(IO流)，03版本就是使用xls结尾
//        FileOutputStream fos = null; // 输出到指定位置
        OutputStream out = null;
//        try {
//            fos = new FileOutputStream("C:\\Users\\46075\\Desktop\\metoo\\ExcelIO\\test\\" + "设备信息.xls");
            //输出
            try {
                response.setCharacterEncoding("UTF-8");
                response.setContentType("application/octet-stream");
                response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode("设备信息.xls", "UTF-8"));
                out = response.getOutputStream();
                // 将创建好的数据写入输出流
                workbook.write(out);
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                //关闭流
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                long end = System.currentTimeMillis();
                System.out.println("耗时："+(end-begin));
            }
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        }
    }

    @ApiOperation("模板下载")
    @GetMapping("/downTemp")
    public Object downTemplate(HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
//        InputStream inputStream = FileUtil.class.getClassLoader().getResourceAsStream(\"/templates/excel/\" + this.batchImportNodeFileName);\n" +
//                "        InputStream in = this.getClass().getResourceAsStream(\"/templates/excel" + this.batchImportNodeFileName);
//        File file = new File("src/main/resources/template/excel/" + this.batchImportNodeFileName);
//        boolean flag = DownLoadFileUtil.downloadZip(file, response);
//        String realPatah = request.getServletContext().getRealPath("");
//        System.out.println(realPatah);
//        String realPath = "src/main/resources/templates/excel/" + this.batchImportNodeFileName;
//        File file = new File(realPath);
//        boolean flag = DownLoadFileUtil.downloadZip(file, response);
//        String name = java.net.URLEncoder.encode(this.batchImportNodeFileName, "UTF-8");
//        InputStream in = FileUtil.class.getClassLoader().getResourceAsStream("static/excel/" + this.batchImportNodeFileName);
//        boolean flag = DownLoadFileUtil.downloadZip(in, this.batchImportNodeFileName, response);
        boolean flag = DownLoadFileUtil.downloadTemplate(this.batchImportFilePath, this.batchImportNeFileName, response);
        if(flag){
            return ResponseUtil.ok();
        }else{
            return ResponseUtil.error();
        }
    }

    @ApiOperation("是否开启凭证")
    @GetMapping("/isCredential")
    public Object isCredential(@RequestParam(value = "uuid") String uuid){
        NetworkElement networkElement = this.networkElementService.selectObjByUuid(uuid);
        if(networkElement != null){
//            // 验证凭据是否存在
//            Credential credential = this.credentialService.getObjById(networkElement.getCredentialId());
//            if(credential != null){
//                return ResponseUtil.ok(1);
//            }else{
//                return ResponseUtil.ok(0);

            Map map = new HashMap();
            map.put("permitConnect", networkElement.isPermitConnect());
            map.put("webUrl", networkElement.getWebUrl());
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument("Uuid不存在");
    }

}
