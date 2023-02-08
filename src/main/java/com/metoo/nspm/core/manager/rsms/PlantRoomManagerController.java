package com.metoo.nspm.core.manager.rsms;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IPlantRoomService;
import com.metoo.nspm.core.service.nspm.IRackService;
import com.metoo.nspm.core.service.nspm.IRsmsDeviceService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.PlantRoomDTO;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.PlantRoomVO;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Api("机房")
@RequestMapping("/admin/plant/room")
@RestController
public class PlantRoomManagerController {

    @Autowired
    private IPlantRoomService plantRoomService;
    @Autowired
    private IRackService rackService;
    @Autowired
    private IRsmsDeviceService rsmsDeviceService;

    @ApiOperation("机房列表")
    @RequestMapping("/list")
    public Object list(@RequestBody PlantRoomDTO dto){
        Page<PlantRoom> page = this.plantRoomService.selectConditionQuery(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<Role>(page));
        }
        return ResponseUtil.ok();
    }

    @GetMapping("/rackList")
    public Object rackList(@RequestParam("id") Long id){
        PlantRoom plantRoom = this.plantRoomService.getObjById(id);
        Rack rack = new Rack();
        rack.setPlantRoomId(plantRoom.getId());
        List<Rack> rackList = this.rackService.query(rack);
        // 遍历得到rack的使用信息
        List list = new ArrayList();
        for (Rack obj : rackList){
            list.add(this.rackService.rack(obj.getId()));
        }
        return ResponseUtil.ok(list);
    }

//    @PostMapping("/cart")
//    public Object cart(@RequestBody PlantRoomDTO dto){
//       List<PlantRoom> plantRoomList = this.plantRoomService.selectObjByCard();
//       if(plantRoomList.size() > 0){
//           plantRoomList.forEach((item) -> {
//               PlantRoom plantRoom = this.plantRoomService.getObjById(item.getId());
//               Map params = new HashMap();
//               params.put("plantRoomId", plantRoom.getId());
//               List<Rack> rackList = this.rackService.selectObjByMap(params);
//               if(rackList.size() > 0){
//                    rackList.forEach((rackItem) -> {
//                        Rack rack = this.rackService.getObjById(rackItem.getId());
//
//                    });
//               }
//           });
//
//       }
//       return ResponseUtil.ok(plantRoomList);
//    }

    @ApiOperation("机柜卡片")
    @GetMapping("/cart")
    public Object cart(){
        List<PlantRoom> plantRoomList = this.plantRoomService.selectObjByCard();
//        List list = new ArrayList();
//        if(plantRoomList.size() > 0){
//           plantRoomList.forEach((item) -> {
//               PlantRoom plantRoom = this.plantRoomService.getObjById(item.getId());
//               Map params = new HashMap();
//               params.put("plantRoomId", plantRoom.getId());
//               List<Rack> rackList = this.rackService.selectObjByMap(params);
//               if(rackList.size() > 0){
//                   List<Rack> racks = plantRoom.getRackList();
//                    rackList.forEach((rackItem) -> {
//                        Rack rack = this.rackService.getObjById(rackItem.getId());
//                        params.clear();
//                        params.put("rackId", rack.getId());
//                        List<RsmsDevice> deviceList = this.rsmsDeviceService.selectObjByMap(params);
//                        rack.setNumber(deviceList.size());
//                        int size = 0;
//                        for(RsmsDevice device : deviceList){
//                            if(device.getStart() > 0 && device.getSize() > 0){
//                                size += device.getSize();
//                            }
//                        }
//                        rack.setSurplusSize(rack.getSize() - size);
//                        racks.add(rack);
//                    });
//               }
//               list.add(plantRoom);
//           });
            return ResponseUtil.ok(plantRoomList);
    }

    @ApiOperation("/新增或更新机房")
    @RequestMapping("/save")
    public Object save(@RequestBody PlantRoom instance){
        if(instance == null){
            return ResponseUtil.badArgument();
        }
        if(StringUtils.isEmpty(instance.getName())){
            return ResponseUtil.badArgument("机房名称不能为空");
        }
        if(!StringUtils.isEmpty(instance.getName())){
          Map params = new HashMap();
          params.put("name", instance.getName());
          params.put("plantRoomId", instance.getId());
          List<PlantRoomVO> plantRooms = this.plantRoomService.selectVoByMap(params);
          if(plantRooms.size() > 0){
              return ResponseUtil.badArgumentRepeatedName();
          }
        }
        int flag = this.plantRoomService.save(instance);
        if (flag != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error("机房保存失败");
    }

    @ApiOperation("删除机房")
    @DeleteMapping("/del")
    public Object del(@RequestParam(value = "id") String id){
        PlantRoom instance = this.plantRoomService.getObjById(Long.parseLong(id));
        if(instance == null){
            return ResponseUtil.badArgument("资源不存在");
        }
        if(instance.getDeleteStatus() == 1){
            return ResponseUtil.badArgument("默认机房不允许删除");
        }
        // 查询预置机房
        PlantRoom plantRoom = new PlantRoom();
        plantRoom.setDeleteStatus(1);
        List<PlantRoomVO> vo = this.plantRoomService.query(plantRoom);
        // 查询所有机柜
        Rack rack = new Rack();
        rack.setPlantRoomId(instance.getId());
        List<Rack> rackList = this.rackService.query(rack);
        for(Rack obj : rackList){
            obj.setPlantRoomId(vo.get(0).getId());
            this.rackService.update(obj);
        }
        User user = ShiroUserHolder.currentUser();
        Map params = new HashMap();
        params.put("userId", user.getId());
        params.put("plantRoomId", instance.getId());
        // 更新设备
        List<RsmsDevice> rsmsDevices = this.rsmsDeviceService.selectObjByMap(params);
        for (RsmsDevice rsmsDevice : rsmsDevices){
            rsmsDevice.setPlantRoomId(vo.get(0).getId());
            try {
                this.rsmsDeviceService.update(rsmsDevice);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        int flag = this.plantRoomService.delete(Long.parseLong(id));
        if (flag != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error("机房删除失败");
    }
    @ApiOperation("批量删除机房")
    @DeleteMapping("/batch/del")
    public Object batchDel(@RequestParam(value = "ids") String ids){
        String[] l = ids.split(",");
        List<String> list = Arrays.asList(l);
        for (String id : list){
            PlantRoom instance = this.plantRoomService.getObjById(Long.parseLong(id));
            if(instance == null){
                return ResponseUtil.badArgument("id：" + id + "资源不存在");
            }
            if(instance.getDeleteStatus() == 1){
                return ResponseUtil.badArgument("默认机房不允许删除");
            }
            // 查询预置机房
            PlantRoom plantRoom = new PlantRoom();
            plantRoom.setDeleteStatus(1);
            List<PlantRoomVO> vo = this.plantRoomService.query(plantRoom);
            // 查询所有机柜
            Rack rack = new Rack();
            rack.setPlantRoomId(instance.getId());
            List<Rack> rackList = this.rackService.query(rack);
            for(Rack obj : rackList){
                obj.setPlantRoomId(vo.get(0).getId());
                this.rackService.update(obj);
            }
            User user = ShiroUserHolder.currentUser();
            Map params = new HashMap();
            params.put("userId", user.getId());
            params.put("plantRoomId", instance.getId());
            // 更新设备
            List<RsmsDevice> rsmsDevices = this.rsmsDeviceService.selectObjByMap(params);
            for (RsmsDevice rsmsDevice : rsmsDevices){
                rsmsDevice.setPlantRoomId(vo.get(0).getId());
                try {
                    this.rsmsDeviceService.update(rsmsDevice);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        int flag = this.plantRoomService.batchDel(ids);
        if (flag != 0){
            return ResponseUtil.ok();
        }
        return ResponseUtil.error("机房删除失败");
    }

}
