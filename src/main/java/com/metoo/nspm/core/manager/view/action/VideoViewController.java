package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.manager.view.tools.WebLiveRoomTools;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.VideoDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.req.VideoReq;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("客户端视频管理")
@RestController
@RequestMapping("/web/video")
public class VideoViewController {

    @Autowired
    private IVideoService videoService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private WebLiveRoomTools webLiveRoomTools;
    @Autowired
    private IAccessoryService accessoryService;

    public static void main(String[] args) {
        Map params = new HashMap();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        params.put("begin", sdf.format(CommUtils.appointedDay(0)));
        params.put("end", sdf.format(CommUtils.appointedDay(30)));
        System.out.println(params.toString());
    }

    /*@RequestMapping("/list")
    public Object list(Integer currentPage, Integer pageSize, String type,
                       String grade, String course, Integer addTime, String orderBy, String orderType){
        Map map = new HashMap();
        if(currentPage == null){
            currentPage = 1;
        }
        if(pageSize == null){
            pageSize = 15;
        }
        Map params = new HashMap();
        params.put("currentPage", currentPage);
        params.put("pageSize", pageSize);
        params.put("orderType", orderType);
        params.put("orderBy", orderBy);*//*
        params.put("grade", grade);
        params.put("course", course);*//*
        params.put("display", 1);
        params.put("status", 1);
        params.put("startTime", CommUtils.appointedDay(addTime == null ? 8 : addTime + 1));
        params.put("endTime", CommUtils.appointedDay(0));
        params.put("type", type);

        List<Video> videoList =  this.videoService.findBycondition(params);
        map.put("obj", videoList);
        map.put("currentPage", currentPage);
        map.put("pageSize", videoList.s));

        return ResponseUtil.ok(map);
    }*/

//    @RequiresPermissions("WEB:VIDEO:LIST")
    @ApiOperation("客户端视频列表")
    @PostMapping("/list")
    public Object list(@RequestBody(required = false) VideoDto dto){

        Map data = new HashMap();
        SysConfig config = this.configService.select();
        if(dto.getCurrentPage() == null){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null){
            dto.setPageSize(15);
        }
        if(dto.getAddTime() != null){
            dto.setBeginTime(CommUtils.appointedDay(dto.getAddTime() == null ? -6 : ~(dto.getAddTime())+2));
            dto.setEndTime(CommUtils.appointedDay(1));
        }
   /*     Map params = new HashMap();
        params.put("currentPage", currentPage);
        params.put("pageSize", pageSize);
        params.put("orderType", orderType);
        params.put("orderBy", orderBy);*//*
        params.put("grade", grade);
        params.put("course", course);*//*
        params.put("display", 1);
        params.put("status", 1);
        params.put("startTime", CommUtils.appointedDay(addTime == null ? 8 : addTime + 1));
        params.put("endTime", CommUtils.appointedDay(0));
        params.put("type", type);
*/
        dto.setDisplay(1);
        dto.setStatus(1);
        dto.setIsEnable(1); // 默认0：关闭 1：开启
        dto.setOrderBy("addTime");
        dto.setOrderType("DESC");

        Page<Video> page =  this.videoService.query(dto);

        data.put("obj", page.getResult());
        data.put("currentPage", page.getPageNum());
        data.put("pageSize", page.getPageNum());
        data.put("pages", page.getPages());
        data.put("total", page.getTotal());
        data.put("domain", config.getDomain());
        return ResponseUtil.ok(data);
    }


    /**
     * 添加直播和视频不能是同时播放判断（弃用）
     * @param req
     * @return
     */
//    @RequiresPermissions("WEB:VIDEO:DETAIL")
    @ApiOperation("客户端视频详情")
    @RequestMapping("/detail")
    public Object videoList(@RequestBody(required = true) VideoReq req){
        Map map = new HashMap();
        SysConfig config = this.configService.select();
        Video video = this.videoService.selectPrimaryById(req.getId());
        LiveRoom liveRoom = null;
        // 查询当前直播间是否有直播未结束
        if(video != null){
            if(video.getType() == 1){
               RoomProgram roomProgram = this.roomProgramService.findObjById(video.getRoomProgramId());
               liveRoom = this.liveRoomService.getObjById(video.getLiveRoomId());
               video.setRoomProgram(roomProgram);
            }else{
                liveRoom = this.liveRoomService.getObjById(video.getLiveRoomId());
           }
            if(liveRoom == null){
                return ResponseUtil.badArgument("直播间已关闭");
            }
            /* if(!this.webLiveRoomTools.exists(liveRoom.getId())){
                    return ResponseUtil.badArgument("直播间正在直播");
                }*/
            if(liveRoom.getIsEnable() == 0){
                return ResponseUtil.badArgument("直播间被禁用");
            }
            Map params = new HashMap();
            params.put("status", 1);
            params.put("roomId", liveRoom.getId());
            List<RoomProgram> roomProgramList = this.roomProgramService.findRoomProgramByLiveRoomId(params);
            if(roomProgramList.size() > 0){
                map.put("roomProgram", roomProgramList.get(0));
            }
            Accessory accessory = this.accessoryService.getObjById(liveRoom.getCover());
            if(accessory != null){
                liveRoom.setPhoto(config.getDomain() + "/" + accessory.getA_path() + "/" + accessory.getA_name());
            }
            video.setLiveRoom(liveRoom);
            map.put("obj", video);
            params.clear();
            params.put("currentPage", 1);
            params.put("pageSize", 1500);
            params.put("orderBy", "type ASC, mv.addTime DESC, mv.sequence DESC");
//            params.put("orderType", "DESC");
            params.put("status", 1);
            params.put("display", 1);
            params.put("liveRoomId", liveRoom.getId());
            List<Video> videoList = this.videoService.findObjByMap(params);
            map.put("videoList", videoList);
            map.put("domain", config.getDomain());
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument();
    }

    @RequestMapping("/captcha")
    public Object captcha(){
        return CommUtils.randomString(6);
    }
}
