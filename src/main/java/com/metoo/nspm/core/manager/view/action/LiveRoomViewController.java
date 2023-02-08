package com.metoo.nspm.core.manager.view.action;

import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.LiveRoomDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.CourseVo;
import com.metoo.nspm.vo.WebLiveRoomVo;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("客户端直播间")
@RestController
@RequestMapping("/web/liveRoom")
public class LiveRoomViewController {

    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private IGradeService gradeService;
    @Autowired
    private ICourseService courseService;
    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private IVideoService videoService;
    @Autowired
    private IAccessoryService accessoryService;

//    @RequiresPermissions("WEB:LIVOROOM:LIST")
    @ApiOperation("直播间列表")
    @RequestMapping("/list")
    public Object list(@RequestBody LiveRoomDto dto){
        Map data = new HashMap();
        if(dto.getCurrentPage() == null && dto.getCurrentPage() < 0){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null && dto.getPageSize() < 0){
            dto.setPageSize(15);
        }
        if (dto.getOrderBy() == null || dto.getOrderBy().equals("")) {
            dto.setOrderBy("mlr_live DESC, mlr.obs DESC, mlr_lastTime DESC");
        }
        /*if (dto.getOrderType() == null || dto.getOrderType().equals("")) {
            dto.setOrderType("ASC");
        }*/
        Map params = new HashMap();
        params.put("currentPage", dto.getCurrentPage());
        params.put("pageSize", dto.getPageSize());
        params.put("orderType", dto.getOrderType());
        params.put("orderBy", dto.getOrderBy());
        params.put("grade", dto.getGrade());
        params.put("course", dto.getCourse());
        params.put("isEnable", 1);
        params.put("deleteStatus", 0);
        Page<WebLiveRoomVo> page = this.liveRoomService.webLiveRoom(params);
        if(page.size() > 0){
            data.put("pageSize", page.size());
            data.put("currentPage", dto.getCurrentPage());
            data.put("obj", page.getResult());
            data.put("pages", page.getPages());
        }
        return ResponseUtil.ok(data);
    }

//    @RequiresPermissions("WEB:LIVEROOM:DETAIL")
    @ApiOperation("直播节目")
    @RequestMapping("/detail")
    public Object EnterStudio(@RequestBody LiveRoomDto dto){
        Map data = new HashMap();
        LiveRoom liveRoom = this.liveRoomService.getObjById(dto.getId());
        if(liveRoom == null){
            return ResponseUtil.badArgument();
        }
        Map params = new HashMap();
        params.put("status", 1);
        params.put("roomId", liveRoom.getId());
        List<RoomProgram> roomProgramList = this.roomProgramService.findRoomProgramByLiveRoomId(params);

        if(roomProgramList.size() > 0){
            RoomProgram roomProgram = roomProgramList.get(0);
            if(roomProgram.getStatus() == 1){
                liveRoom.setRtmp(liveRoom.getRtmp() + "/index.m3u8");
                liveRoom.setRoomProgram(roomProgram);
            }
        }else{
            liveRoom.setRtmp(null);
            liveRoom.setLive(0);
           /* liveRoom.setAccessory(accessory);*/
        }
        Accessory accessory = this.accessoryService.getObjById(liveRoom.getCover());
        if(accessory != null){
            String photo = this.configService.select().getDomain()
                    + "/"
                    + accessory.getA_path()
                    + "/"
                    + accessory.getA_name();
            liveRoom.setPhoto(photo);
        }
        data.put("obj", liveRoom);
        // 当前直播间下的上传视频
        params.clear();
        params.put("currentPage", 1);
        params.put("pageSize", 1500);
        params.put("type", 0);
        params.put("display", 1);
        params.put("status", 1);
        params.put("liveRoomId", liveRoom.getId());
        params.put("startTime", 8);
        params.put("endTime", CommUtils.appointedDay(0));
        params.put("orderBy", "sequence");
        params.put("orderType", "DESC");
        Map video = new HashMap();

        List<Video> videoList = this.videoService.findObjByMap(params);
        video.put("videoList", videoList);
        video.put("currentPage", 1);
        video.put("pageSize", videoList.size());

        Map playBack = new HashMap();
        params.put("type", 1);
        List<Video> playBackList = this.videoService.findObjByMap(params);
        playBack.put("playBackList", playBackList);
        playBack.put("currentPage", 1);
        playBack.put("pageSize", videoList.size());

        data.put("video", video);
        data.put("playBack", playBack);
        return ResponseUtil.ok(data);
    }

    public void getClass(Map map){
        List<Grade> gradeList = this.gradeService.webGradeList(null);
        map.put("gradeList", gradeList);
        List<CourseVo> courseList = this.courseService.webCourseList();
        map.put("courseList", courseList);
    }
}
