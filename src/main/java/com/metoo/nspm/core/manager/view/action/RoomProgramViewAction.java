package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.service.nspm.ILiveRoomService;
import com.metoo.nspm.core.service.nspm.IRoomProgramService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.entity.nspm.LiveRoom;
import com.metoo.nspm.entity.nspm.RoomProgram;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.vo.Result;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("客户端直播")
@RestController
@RequestMapping("/web/program")
public class RoomProgramViewAction {

    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private ISysConfigService sysConfigService;

//    @RequiresPermissions("WEB:PROGRAM:LIST")
    @ApiOperation("客户端直播列表")
    @RequestMapping("/list")
    public Object webProgram(){
        Map<String, Object> map = new HashMap<String, Object>();
        Map params = new HashMap();
        params.put("status", 1);
        List<RoomProgram> roomPrograms = this.roomProgramService.findObjByCondition(params);
        if(roomPrograms != null && roomPrograms.size() > 0){
            LiveRoom liveRoom = this.liveRoomService.getObjById(roomPrograms.get(0).getRoomId());
            String bindCode = "";
            String rtmp = "";
            if(liveRoom != null){
                bindCode = liveRoom.getBindCode();
                rtmp = liveRoom.getRtmp();
                map.put("live", liveRoom.getLive());
            }
            map.put("roomProgram", roomPrograms.get(0));
            map.put("rtmp", rtmp + "/index.m3u8");

            map.put("status", roomPrograms.get(0).getStatus());
        }else{
            // 默认查询唯一直播间
            List<LiveRoom> liveRoomList = this.liveRoomService.findAllLiveRoom();
            if(liveRoomList.size() > 0){
                LiveRoom liveRoom = liveRoomList.get(0);
                String bindCode = "";
                String rtmp = "";
                if(liveRoom != null){
                    bindCode = liveRoom.getBindCode();
                    rtmp = liveRoom.getRtmp();
                    map.put("live", liveRoom.getLive());
                }
                map.put("rtmp", rtmp + "/index.m3u8");
            }
        }
        SysConfig sysConfig = this.sysConfigService.select();
        map.put("title", sysConfig.getTitle());
        return new Result(200, "Successfully", map);
    }

    @RequestMapping("/liveStatus")
    public Object liveStatus(){
        Map params = new HashMap();
        params.put("status", 1);
        List<RoomProgram> roomProgramList = this.roomProgramService.liveStatus(params);
        Map map = new HashMap();
        if(roomProgramList.size() > 0){
            RoomProgram obj = roomProgramList.get(0);
            map.put("id", obj.getId());
            map.put("status", obj.getStatus());
            //map.put("live", obj.getLive());
        }
        return new Result(200, "Successfully", map);
    }
}
