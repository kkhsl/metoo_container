package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.MonitorTools;
import com.metoo.nspm.core.manager.admin.tools.PlayBackTools;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.utils.file.FileUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.MonitorDto;
import com.metoo.nspm.dto.RoomProgramDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import io.swagger.annotations.ApiModelProperty;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * Title: RoomProgramManagerAction.java
 * </p>
 *
 * <p>
 * Description: 直播节目管理控制器；负责创建直播节目，多个节目可对应一个直播间
 *
 * </p>
 */
@ApiOperation("直播管理")
@RestController
@RequestMapping("/admin/program")
public class RoomProgramManagerController {

    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private PlayBackTools playBackTools;
    @Autowired
    private IGradeService gradeService;
    @Autowired
    private ICourseService courseService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private MonitorTools monitorTools;

    /*@RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation(value = "直播列表")
    @RequestMapping("/list")
    public Object program(@RequestBody RoomProgramDto dto) {
        Map map = new HashMap();
        if (dto.getCurrentPage() == null || dto.getCurrentPage().equals("")) {
            dto.setCurrentPage(1);
        }
        if (dto.getPageSize() == null || dto.getPageSize().equals("")) {
            dto.setPageSize(15);
        }
        int total = this.roomProgramService.getAccountByTotal();// 获取总数
        if(total > 0){
            int totalPages = total / dto.getCurrentPage();
            int left = total % dto.getPageSize();
            if (left > 0) {
                totalPages += 1;
            }

            int startRow = (dto.getCurrentPage() - 1) * dto.getPageSize();// 起始行
            Map<String, Object> params = new HashMap<String, Object>();
            params.put("startRow", startRow);
            params.put("pageSize", dto.getPageSize());
            User user = ShiroUserHolder.currentUser();
            *//*Long userId = null;
            Integer type = null;
            if(!user.getUserRole().equals("SUPPER")){
                // 控制类型参数只能为0：避免前端随意传参
                if(user.getUserRole().equals("ADMIN")){ // 只有管理员才可筛选所有用户直播
                    if(dto.getType() == null || dto.getType() != 0){
                        userId = user.getId();
                    }else{
                        type = 0;
                    }
                }else{
                    userId = user.getId();
                }
            }*//*
            params.put("userId", user.getId());
            params.put("deleteStatus", 0);
            List<RoomProgram> roomProgramList = this.roomProgramService.getRoomProgram(params);
            map.put("pageSize", roomProgramList.size());
            map.put("total", total);
            map.put("currentPage", dto.getCurrentPage());
            map.put("obj", roomProgramList);
            map.put("pages", totalPages);
        }
        return ResponseUtil.ok(map);
    }*/

    @RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation(value = "直播列表")
    @RequestMapping("/list")
    public Object list(@RequestBody(required = false) RoomProgramDto dto) {
        User user = ShiroUserHolder.currentUser();
        if (dto == null) {
            dto = new RoomProgramDto();
        }
        dto.setUserId(user.getId());
        Page<RoomProgram> page = this.roomProgramService.query(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<RoomProgram>(page));
        }
        return ResponseUtil.ok();
    }

    @RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation(value = "直播添加")
    @RequestMapping("/add")
    public Object add(){
        User user = ShiroUserHolder.currentUser();
        Map map = new HashMap();
        Map<String, Object> params = new HashMap<String, Object>();
        params.put("currentPage", 1);
        params.put("pageSize", 15);
        params.put("display", 1);
        List<Course> courseList = this.courseService.findBycondition(params);
        List<Grade> grades = this.gradeService.findBycondition(params);
        map.put("courseList", courseList);
        map.put("gradeList", grades);

/*        params.clear();
        params.put("userId", user != null ? user.getId() : null);
        params.put("startRow", 0);
        params.put("pageSize", 15);
        List<LiveRoom> liveRooms = this.liveRoomService.query(params);
        map.put("liveRoomList", liveRooms);*/

        return ResponseUtil.ok(map);
    }

    @RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation("直播更新")
    @RequestMapping("/update")
    public Object update(@RequestBody RoomProgramDto dto){
        Map map = new HashMap();
        Map<String, Object> params = new HashMap<String, Object>();
        RoomProgram roomProgram = this.roomProgramService.findObjById(dto.getId());
        if(roomProgram != null){
        map.put("obj", roomProgram);
        if(roomProgram.getRoomId() != null){
            LiveRoom liveRoom = this.liveRoomService.getObjById(roomProgram.getRoomId());
            map.put("liveRoom", liveRoom);
        }
        params.clear();
        params.put("currentPage", 1);
        params.put("pageSize", 15);
        params.put("display", 1);
        List<Course> courseList = this.courseService.findBycondition(params);
        List<Grade> grades = this.gradeService.findBycondition(params);
        map.put("courseList", courseList);
        map.put("gradeList", grades);

/*         User user = ShiroUserHolder.currentUser();
       params.clear();
        params.put("userId", user != null ? user.getId() : null);
        params.put("startRow", 0);
        params.put("pageSize", 15);
        List<LiveRoom> liveRooms = this.liveRoomService.query(params);
        map.put("liveRoomList", liveRooms);*/
        return ResponseUtil.ok(map);
      }
      return ResponseUtil.badArgument();
    }

    @RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation(value = "直播保存")
    @RequestMapping("/save")
    public Object save(@RequestBody RoomProgramDto dto){
        if(dto != null){
           if(this.roomProgramService.save(dto)){
                return ResponseUtil.ok();
           }
           return ResponseUtil.error();
        }
        return ResponseUtil.badArgument();
    }

    /**
     * 直播节目添加
     * @param
     * @return
     */
  /*  @RequestMapping("/save")
    @RequiresPermissions("ADMIN_PROGRAM_SAVE")
    public Object save(@RequestBody(required = false) RoomProgram roomprogram) {
        return this.roomProgramService.save(roomprogram);
    }*/

/*    @RequestMapping("/update")
    @RequiresPermissions("ADMIN_PROGRAM_UPDATE")
    public Object update(HttpServletRequest request, HttpServletResponse response, @RequestBody(required = false) RoomProgram instance){
        return this.roomProgramService.update(instance);
    }*/

    @RequiresPermissions("LK:ROOMPROGRAM")
    @RequestMapping("/delete")
    public Object delete(@RequestBody RoomProgramDto dto){
        if(dto.getId() != null && !dto.getId().equals("")){
            try {
                this.roomProgramService.delete(dto.getId());
                return new Result(200, "Success");
            } catch (Exception e) {
                e.printStackTrace();
                return new Result(500, e.getMessage());
            }
        }else{
            return new Result(400, "Parameter is null");
        }
    }

    /**
     * 创建直播节目-默认创建直播间
     * @param response
     * @param request
     * @param
     * @return
     */
    @ApiOperation("直播")
    @RequestMapping(value = "/liveroom", method = RequestMethod.POST)
    public Object ProgramLiveRoom(HttpServletResponse response, HttpServletRequest request, @RequestBody(required = false) RoomProgram roomProgram){

        return this.roomProgramService.programLiveRoom(roomProgram);
    }

    /**
     * 开启关闭直播
     * @param
     * @return
     */
    @RequiresPermissions("LK:ROOMPROGRAM")
    @ApiOperation("直播修改")
    @RequestMapping("/change")
    public Object changeRoomProgram(@RequestBody RoomProgramDto dto) throws IOException {
        RoomProgram obj = this.roomProgramService.findObjById(dto.getId());
        if(obj != null){ // off
            if(dto.getIsPlayback() != null){
                obj.setIsPlayback(obj.getIsPlayback() == 0 ? 1 : 0);
                if(this.roomProgramService.update(obj)){
                    return ResponseUtil.ok();
                }
                return ResponseUtil.error();
            }
            String path = null;
            SysConfig sysconfig = this.sysConfigService.select();
            LiveRoom liveRoom = this.liveRoomService.getObjById(obj.getRoomId());
            if(liveRoom.getIsEnable() != 1 ){
                return ResponseUtil.badArgument("请先开启直播间");
            }
            if(liveRoom != null){
                if(liveRoom.getBindCode() != null){
                    path = sysconfig.getPath() + File.separator + liveRoom.getBindCode();
                }
                // 获取时间戳
                String timestamp = "";
                if (obj.getStatus() == 1) {
                    timestamp = obj.getTimestamp();
                    obj.setStatus(0);
                    // 创建回放视频
                    if(obj.getIsPlayback() == 1){
                        boolean flag = this.playBackTools.create(liveRoom.getId(), obj, liveRoom.getBindCode());
                        if(flag){
                            obj.setPlayback(1);
                        }
                    }else{
                        // 删除所有TS文件
                        path = sysconfig.getPath() + File.separator + liveRoom.getBindCode();
                        FileUtil.delFileTs(path);
                        String m3u8 = path + File.separator + "index.m3u8";
                        FileUtil.delFile(m3u8);
                    }
                    try {
                        this.roomProgramService.update(obj);
                        liveRoom.setLive(0);
                        liveRoom.setRoomProgramId(null);
                        this.liveRoomService.update(liveRoom);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    // 修改目录权限
                    if(path != null){
                        FileUtil.storeFile(path);
                    }
                }else{
                    // 查询当前直播间是否有直播或视频未关闭
                    Map params = new HashMap();
                    params.put("roomId", liveRoom.getId());
                    params.put("status", 1);
                    List<RoomProgram> roomPrograms = this.roomProgramService.findObjByCondition(params);
                    if(roomPrograms != null && roomPrograms.size()>0){
                        return new Result(202,"当前直播间正在播放: " + roomPrograms.get(0).getTitle());
                    }
                    obj.setStatus(1);// 开启直播
                    // 每次开始直播生成新的时间戳
                    long current_time_millis = System.currentTimeMillis();
                    long timeStampSec = System.currentTimeMillis() / 1000;// 13位时间戳（单位毫秒）转换为10位字符串（单位秒）
                    timestamp = String.format("%010d", timeStampSec);
                    obj.setTimestamp(timestamp);
                    try {
                        this.roomProgramService.update(obj);
                        liveRoom.setLive(1);
                        liveRoom.setLastTime(new Date());
                        liveRoom.setRoomProgramId(obj.getId());
                        this.liveRoomService.update(liveRoom);

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    if(path != null){
                        FileUtil.storeFileOpen(path);
                    }
                }
                // 监控直播状态
                // 1, 每次开启直播生成签名信息
                String sing = "";
                Long liveRoomId = liveRoom.getId();
                Long roomProgramId = obj.getId();
                User user = ShiroUserHolder.currentUser();
                Long userId = user.getId();
                // 2,查询学校Appid
                String appId = sysconfig.getAppId();
                if(appId == null || appId.equals("")){
                    // 3, 生成AppId
                    appId = CommUtils.randomString(6);
                    sysconfig.setAppId(appId);
                    this.configService.update(sysconfig);
                }

                // 4, 创建Sign
                String sign =  liveRoomId + roomProgramId + userId + appId + timestamp;
                sign = this.monitorTools.getSHA256StrJava(sign);

                MonitorDto monitorDto = new MonitorDto();
                monitorDto.setStartTime(timestamp);
                monitorDto.setTitle(sysconfig.getTitle());
                monitorDto.setRoomProgramTitle(obj.getTitle());
                monitorDto.setLiveRoomTitle(liveRoom.getTitle());
                monitorDto.setAppId(appId);
                monitorDto.setSign(sign);
                monitorDto.setUsername(user.getUsername());
                this.monitorTools.monitor(monitorDto);

                return new Result(200, "Success");
            }else{
                return ResponseUtil.badArgument("未关联直播间");
            }
        }else{
            return new Result(400, "Param error");
        }
    }

    /**
     * 直播节目管理
     */

    @RequiresPermissions("LK:ROOMPROGRAM:MANAGER")
    @ApiModelProperty("直播节目管理")
    @RequestMapping("/manager/list")
    public Object managerList(@RequestBody(required = false) RoomProgramDto dto){
        Map map = new HashMap();
        Page<RoomProgram> page = this.roomProgramService.query(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<RoomProgram>(page));
        }
        return ResponseUtil.ok();
    }

    @RequiresPermissions("LK:ROOMPROGRAM:MANAGER")
    @ApiOperation("直播管理更新")
    @RequestMapping("/manager/update")
    public Object managerUpdate(@RequestBody(required = false) RoomProgramDto dto){
        RoomProgram roomProgarm = this.roomProgramService.findObjById(dto.getId());
        if(roomProgarm != null){
            Map map = new HashMap();
            map.put("obj", roomProgarm);
            Map params = new HashMap();
            params.put("currentPage", 1);
            params.put("pageSize", 1);
            params.put("display", 1);
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument("未找到相关资源");
    }

    @RequiresPermissions("LK:ROOMPROGRAM:MANAGER")
    @ApiOperation("平台直播管理保存")
    @RequestMapping("/manager/save")
    public Object managerSave(@RequestBody(required = false) RoomProgramDto dto){
        if(dto != null){
            RoomProgram roomProgram = this.roomProgramService.findObjById(dto.getId());
            if(roomProgram != null){
                if(dto.getStatus() != null){
                    int status = roomProgram.getStatus() == 1 ? 0 : 1;
                    roomProgram.setStatus(status);
                    if(this.roomProgramService.update(roomProgram)){
                        return ResponseUtil.ok();
                    }
                    return ResponseUtil.error();
                }
                return ResponseUtil.ok();
            }
        }
        return ResponseUtil.badArgument("未找到相关资源");
    }
}
