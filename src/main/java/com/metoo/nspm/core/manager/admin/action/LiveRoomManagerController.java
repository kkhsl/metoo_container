package com.metoo.nspm.core.manager.admin.action;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.POJO.QueryFilter;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.LiveRoomDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 *  Title：LiveRoomManagerAction.java
 * </p>
 *
 * <p>
 *  Description: 直播间管理控制器；
 * </p>
 *
 * <p>
 *  author: pers hkk
 * </p>
 */

@Api("直播管理")
@RestController
@RequestMapping(value = "/admin/room/")
public class LiveRoomManagerController {

    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private IVideoService videoService;
    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private IUserService userService;
    @Autowired
    private ISysConfigService configService;


    /**
     * 直播间列表
     * @param
     * @param
     * @return
     */
 /*   @RequiresPermissions("ADMIN:PROGRAM:LIST")
    @ApiOperation("直播列表")
    @RequestMapping(value = "list")
    public Object rooms(HttpServletRequest request, HttpServletResponse response,
                        Integer currentPage, Integer pageSize,String search) {
        Map map = new HashMap();
        // 分页查询
        if(currentPage == null || currentPage.equals("")){
            currentPage = 1;
        }
        if(pageSize == null || pageSize.equals("")){
            pageSize = 2;
        }
        int totalRow = this.liveRoomService.findAccountByTotal();// 查询总数
        if(totalRow > 0){
            int totalPages = totalRow / pageSize;// 总页数
            int left = totalRow % pageSize;
            if(left > 0){
                totalPages += 1;
            }
            // 判断用户是否手动修改页码
            if(currentPage > totalPages){
                currentPage = totalPages;
            }
            // 起始行
            int startRow = (currentPage - 1) * pageSize;
            // 封装分页参数
            Map<String ,Object> params = new HashMap();
            params.put("startRow", startRow);
            params.put("pageSize", pageSize);
            CommUtils.currentUserId(params);
            List<LiveRoom> liveRooms = this.liveRoomService.findByPager(params);
            map.put("totalPages", totalPages);
            map.put("totalRow",totalRow);
            map.put("pageSize", liveRooms.size());
            map.put("list", liveRooms);
        }
        //List<LiveRoom> liveRooms = this.liveRoomService.findAllLiveRoom();
        return new Result(200, "Successfully", map);
    }
*/

//    @RequiresPermissions("ADMIN:LIVEROOM:LIST")

    /*@RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间列表")
    @RequestMapping(value = "/list")
    public Object list(@RequestBody LiveRoomDto dto) {
        SysConfig sysConfig = this.configService.select();
        Map map = new HashMap();
        User user = ShiroUserHolder.currentUser();
        // 分页查询
        if(dto.getCurrentPage() == null || dto.getCurrentPage().equals("")){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null || dto.getPageSize().equals("")){
            dto.setPageSize(15);
        }
        int total = this.liveRoomService.findAccountByTotal();// 查询总数
        if(total > 0){
            int totalPages = total / dto.getPageSize();// 总页数
            int left = total % dto.getPageSize();
            if(left > 0){
                totalPages += 1;
            }
            // 判断用户是否手动修改页码
            if(dto.getCurrentPage() > totalPages){
                dto.setCurrentPage(totalPages);
            }
            // 起始行
            int startRow = (dto.getCurrentPage() - 1) * dto.getPageSize();
            // 封装分页参数
            Map<String ,Object> params = new HashMap();
            params.put("currentPage", startRow);
            params.put("pageSize", dto.getPageSize());

            *//*  if(!user.getUserRole().equals("SUPPER")){
                // 控制类型参数只能为0：避免前端随意传参
              if(user.getUserRole().equals("ADMIN")){ // 只有管理员才可筛选所有用户直播
                    if(dto.getType() == null || dto.getType() != 0){
                        userId = user.getId();
                    }else{
                        type = 0;
                        params.put("type", type);
                    }
                }else{
                    userId = user.getId();
                }
                params.put("userId", user.getId());
            }*//*
            params.put("deleteStatus", 0);
            params.put("userId", user.getId());
            List<LiveRoom> liveRooms = this.liveRoomService.findObjByMap(params);
            map.put("pages", totalPages);
            map.put("total",total);
            map.put("pageSize", liveRooms.size());
            map.put("list", liveRooms);
            map.put("userRole", user.getUserRole());
        }
        return ResponseUtil.ok(map);
    }*/


//    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间列表")
    @PostMapping(value = "/list")
    public Object list(@RequestBody LiveRoomDto dto) {
        if(dto == null){
            dto  = new LiveRoomDto();
        }
        User user = ShiroUserHolder.currentUser();
        dto.setUserId(user.getId());
        Page<LiveRoom> page = this.liveRoomService.query(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<LiveRoom>(page));
        }
        return ResponseUtil.ok();
    }


    /**
     * 更新直播间
     * @param room
     * @return
     */

    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间更新")
    @RequestMapping("update")
    public Object update(@RequestBody LiveRoom room){
        Map params = new HashMap();
        params.put("currentPage", 0);
        params.put("pageSize", 1);
        params.put("id", room.getId());
        List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
        if(liveRoomList.size() > 0){
            SysConfig sysConfig = this.configService.select();
            LiveRoom liveRoom = liveRoomList.get(0);
            User currentUser = ShiroUserHolder.currentUser();
            if(currentUser.getId().equals(liveRoom.getUserId())){
                if(liveRoom != null){
                    return ResponseUtil.ok(liveRoom);
                }
            }
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }
   /* public Object update(@RequestBody  LiveRoom room){
        LiveRoom liveRoom = this.liveRoomService.getObjById(room.getId());
        if(liveRoom != null){
            try {
                this.liveRoomService.update(room);
                return ResponseUtil.ok();
            } catch (Exception e) {
                e.printStackTrace();
                return new Result(500, "Update error");
            }
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }*/

    /**
     * 创建直播间
     * @param
     * @param
     * @param instance
     * @return
     */
//    @RequiresPermissions("ADMIN:LIVEROOM:SAVE")

    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间保存")
    @RequestMapping(value = "save")
    public Object save(@RequestBody LiveRoom instance) {
        if (instance != null) {
            if(instance.getTitle() != null && !instance.getTitle().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                LiveRoom liveRoom = this.liveRoomService.getObjById(instance.getId());
                if(liveRoom != null){
                    if(currentUser.getId().equals(liveRoom.getUserId())){
                        Accessory accessory = this.accessoryService.getObjById(instance.getCover());
                        if(accessory != null){
                            instance.setCover(accessory.getId());
                        }else{
                            instance.setCover(null);
                        }
                        if(this.liveRoomService.save(instance)){
                            return ResponseUtil.ok();
                        }
                    }
                    return ResponseUtil.badArgument("未找到指定资源");
                }
                return ResponseUtil.badArgument("未找到指定资源");
            }
            return ResponseUtil.badArgument("请输入直播间名称");
        }
        return new Result(400,"参数错误");
    }

    /**
     * 删除直播间
     * @param
     * @param
     * @param
     * @return
     */
//    @RequiresPermissions("ADMIN:LIVEROOM:DELETE")

    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间删除")
    @RequestMapping(value = "delete")
    public Object delete(@RequestBody LiveRoomDto dto){

        if(dto.getId() != null || !dto.getId().equals("")){
            LiveRoom liveRoom = this.liveRoomService.getObjById(dto.getId());
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findObjById(liveRoom.getUserId());
            if(currentUser.getId().equals(liveRoom.getUserId())){
                int flag = this.liveRoomService.delete(dto.getId());
                if(flag == 1){
                    // 清除直播关联关系 这里优化为批量更新
                    Map params = new HashMap();
                    params.put("roomId", dto.getId());
                    List<RoomProgram> roomPrograms = this.roomProgramService.findRoomProgramByLiveRoomId(params);
                    if(roomPrograms.size() > 0){
                        for(RoomProgram roomProgram : roomPrograms){
                            System.out.println("========" + roomProgram.getId());
                            roomProgram.setRoomId(null);
                            this.roomProgramService.update(roomProgram);
                        }
                    }

                    // 清除视频关联关系
                    List<Video> videoList = this.videoService.findObjBuLiveRoomId(dto.getId());
                    if(videoList.size() > 0){
                        videoList.forEach((e)->{
                            e.setLiveRoomId(null);
                            this.videoService.update(e);
                        });
                    }
                    return new Result(200, "Succesfully");
                }else{
                    return new Result(500, "Delete Error");
                }
            }else{
                return ResponseUtil.badArgument("未找到指定资源");
            }
        }else{
            return new Result(400, "Parameter error");
        }

    }

    /**
     * 直播间 on/off
     * @return
     */
   /* @RequiresPermissions("ADMIN:PROGRAM:CHANGE")
    @ApiOperation("直播修改")
    @PutMapping("/change")
    public Object changeLiveRoom(HttpServletRequest request, HttpServletResponse response, Integer programId) {
        String id = request.getParameter("property");
        LiveRoom liveRoom = this.liveRoomService.getObjById(Long.valueOf(id));
        if (liveRoom != null) {
            try {
                if (liveRoom.getIsEnable() == 0) {
                    liveRoom.setIsEnable(1);
                    // 合并ts文件、转mp4
                    SysConfig sysconfig = this.sysConfigService.select();
                    String path = sysconfig.getPath() + File.separator +liveRoom.getBindCode();
                    String currentDate = CommUtils.formatTime("yyyyMMddhhmmss", new Date());
                    String playBack = path + File.separator + currentDate;
                    String playBackPath = liveRoom.getRtmp() + File.separator + currentDate;
                    boolean flag = FileUtil.merge(path, playBack);
                    if(flag){
                        // 转mp4
                        String read = playBack + File.separator+ "merge.ts";
                        String writer = playBack + File.separator+ "temp.mp4";

                        // linux
                        boolean convert = ChangeVideo.convert(read, writer);
                        // windows
                       *//*
                        boolean convert = ChangeVideo.convert(read,
                                writer);*//*
                        //创建回放信息
                        ProgramPlayback programPlayback = new ProgramPlayback();
                        programPlayback.setAddTime(new Date());
                        programPlayback.setRoomId(liveRoom.getId());
                        programPlayback.setPath(playBack);
                        programPlayback.setRtmp(playBackPath);
                        programPlayback.setCreate(convert == true ? 0 : 1);
                        RoomProgram roomProgram = this.roomProgramService.program(Long.valueOf(programId));
                        if (roomProgram != null) {
                            programPlayback.setProgramId(roomProgram.getRoomId());
                        }
                        this.programPlaybackService.save(programPlayback);
                    }
                } else {
                    liveRoom.setIsEnable(0);
                }
                this.liveRoomService.update(liveRoom);
                return new Result(200, "Successfully");
            } catch (Exception e) {
                e.printStackTrace();
                return new Result(500, "update Error");
            }
        }else{
            return new Result(400, "Params error");
        }
    }*/

    /**
     * pageHelper 分页
     * @param currentPage
     * @param pageSize
     * @return
     */

    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播PageHelper列表")
    @RequestMapping("/allLiveRoom")
    public Object queryAllLiveRoom(Integer currentPage, Integer pageSize){
        Map map = new HashMap();
        if(currentPage == null || pageSize.equals("")){
            currentPage = 1;
        }
        if(pageSize == null || pageSize.equals("")){
            pageSize = 15;
        }
        List<LiveRoom> liveRoomList = this.liveRoomService.queryLiveRooms(currentPage, pageSize);
        if(liveRoomList.size() > 0){
            map.put("currentPage", currentPage);
            map.put("pageSize", liveRoomList.size());
            map.put("liveRoomList", liveRoomList);
        }
        return new Result(200, "Successfully", map);
    }

    /**
     * {"op":{"order_id":"like","user_name":"like","goods_name":"like","addTime":"range"},
     * "filter":{"addTime":["2021-05-16 00:00:00","2021-05-20 00:00:00"],
     * "order_id":"3","user_name":"3","order_cat":5,"goods_name":"3"},
     * "limit":10,"offset":1}
     */
    /**
     * pageHelper 分页
     * @param query
     * @return
     */

    @RequiresPermissions("LK:ROOM")
    @RequestMapping("/liverooms")
    public Object liveroom(String query){
        Map map = new HashMap();
        int currentPage = 1;
        int pageSize = 15;
        if(query != null && !query.equals("")){
            QueryFilter queryFilter = new QueryFilter();
            JSONObject jo =  JSONObject.parseObject(query);
            queryFilter.setWildcard((JSONObject) jo.get("filter"));
            queryFilter.setFiltrate((JSONObject)jo.get("op"));
            queryFilter.setCurrentPage(Integer.parseInt(jo.get("limit").toString()));
            queryFilter.setPageSize(Integer.parseInt(jo.get("offset").toString()));
        }

        List<LiveRoom> liveRoomList = this.liveRoomService.queryLiveRooms(currentPage, pageSize);
        map.put("currentPage", currentPage);
        map.put("pageSize", liveRoomList.size());
        map.put("obj", liveRoomList);
        return new Result(200, "Successfully", map);
    }

    /**
     * 直播间修改
     * @param dto
     * @return
     */
//    @RequiresPermissions("ADMIN:LIVEROOM:CHANGE")

    @RequiresPermissions("LK:ROOM")
    @ApiOperation("直播间修改")
    @RequestMapping("/change")
    public Object change(@RequestBody LiveRoomDto dto){
        LiveRoom liveRoom = this.liveRoomService.getObjById(dto.getId());
        if(liveRoom != null){
            User user = ShiroUserHolder.currentUser();
            if(liveRoom.getUserId().equals(user.getId())){
                int isEnable = liveRoom.getIsEnable() == 1 ? 0 : 1;
                liveRoom.setIsEnable(isEnable);
                if(this.liveRoomService.update(liveRoom) == 1){
                    return ResponseUtil.ok();
                }else{
                    return ResponseUtil.error();
                }

            }
            return ResponseUtil.badArgument("未找到指定资源");
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }
   /* public Object change(@RequestBody LiveRoomDto dto){
        LiveRoom liveRoom = this.liveRoomService.getObjById(dto.getId());
        if(liveRoom != null){
            User user = ShiroUserHolder.currentUser();
            if(liveRoom.getUserId().equals(user.getId())){
                if(dto.getIsPlayback() != null){
                    int isPlayBack = liveRoom.getIsPlayback() == 1 ? 0 : 1;
                    liveRoom.setIsPlayback(isPlayBack);
                }
                if(dto.getIsEnable() != null){
                    int isEnable = liveRoom.getIsEnable() == 1 ? 0 : 1;
                    liveRoom.setIsEnable(isEnable);
                }
                if(this.liveRoomService.update(liveRoom) == 1){
                    return ResponseUtil.ok();
                }else{
                    return ResponseUtil.error();
                }

            }
            return ResponseUtil.badArgument("未找到指定资源");
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }*/




//    @RequiresPermissions("ADMIN:MANAGERLIVEROOM:LIST")

    @RequiresPermissions("LK:ROOM:MANAGER")
    @ApiOperation("直播间管理-列表")
    @RequestMapping(value = "/manager/list")
    public Object buyerLiveRoom(@RequestBody LiveRoomDto dto) {
        Map map = new HashMap();
        Page<LiveRoom> page  = this.liveRoomService.query(dto);
        if(page.getResult().size() > 0){
            return ResponseUtil.ok(new PageInfo<LiveRoom>(page));
        }
        return ResponseUtil.ok();
    }

    /**
     * 更新直播间
     * @param room
     * @return
     */
//    @RequiresPermissions("ADMIN:MANAGERLIVEROOM:UPDATE")
    @RequiresPermissions("LK:ROOM:MANAGER")
    @ApiOperation("直播间管理-更新")
    @RequestMapping("/manager/update")
    public Object managerUpdate(@RequestBody LiveRoom room){
        LiveRoom liveRoom = this.liveRoomService.getObjById(room.getId());
        if(liveRoom != null){
            return ResponseUtil.ok(liveRoom);
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }

    /**
     * 直播间修改
     * @param dto
     * @return
     */
//    @RequiresPermissions("ADMIN:MANAGERLIVEROOM:CHANGE")
    @RequiresPermissions("LK:ROOM:MANAGER")
    @ApiOperation("直播间管理-修改")
    @RequestMapping("/manager/change")
    public Object managerChange(@RequestBody LiveRoomDto dto){
        LiveRoom liveRoom = this.liveRoomService.getObjById(dto.getId());
        if(liveRoom != null){
            int isEnable = liveRoom.getIsEnable() == 1 ? 0 : 1;
            liveRoom.setIsEnable(isEnable);
            if(this.liveRoomService.update(liveRoom) == 1){
                return ResponseUtil.ok();
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument("未找到指定资源");
    }

    /**
     * 直播间保存
     * @param
     * @param
     * @param instance
     * @return
     */
//    @RequiresPermissions("ADMIN:LIVEROOM:SAVE")
    @RequiresPermissions("LK:ROOM:MANAGER")
    @ApiOperation("直播间管理-保存")
    @RequestMapping(value = "/manager/save")
    public Object managerSave(@RequestBody LiveRoom instance) {
        if (instance != null) {
//            LiveRoom liveRoom = this.liveRoomService.getObjById(instance.getId());
//            if(liveRoom != null){
                Accessory accessory = this.accessoryService.getObjById(instance.getCover());
                if(accessory != null){
                    instance.setCover(accessory.getId());
                }else{
                    instance.setCover(null);
                }
                if(this.liveRoomService.save(instance)){
                    return ResponseUtil.ok();
                }
//           }
//            return ResponseUtil.badArgument("未找到指定资源");
        }
        return new Result(400,"Parameter Error");
    }


    /**
     * 删除直播间
     * @param
     * @param
     * @param
     * @return
     */
//    @RequiresPermissions("ADMIN:MANAGERLIVEROOM:DELETE")
    @RequiresPermissions("LK:ROOM:MANAGER")
    @ApiOperation("直播间管理-删除")
    @RequestMapping(value = "/manager/delete")
    public Object managerDelete(@RequestBody LiveRoomDto dto){
        if(dto.getId() != null || !dto.getId().equals("")){
            int flag = this.liveRoomService.delete(dto.getId());
            if(flag == 1){
                // 清除直播关联关系 这里优化为批量更新
                Map params = new HashMap();
                params.put("roomId", dto.getId());
                List<RoomProgram> roomPrograms = this.roomProgramService.findRoomProgramByLiveRoomId(params);
                if(roomPrograms.size() > 0){
                    for(RoomProgram roomProgram : roomPrograms){
                        roomProgram.setRoomId(null);
                        this.roomProgramService.update(roomProgram);
                    }
                }

                // 清除视频关联关系
                List<Video> videoList = this.videoService.findObjBuLiveRoomId(dto.getId());
                if(videoList.size() > 0){
                    videoList.forEach((e)->{
                        e.setLiveRoomId(null);
                        this.videoService.update(e);
                    });
                }
                return new Result(200, "Succesfully");
            }else{
                return new Result(500, "Delete Error");
            }
        }else{
            return new Result(400, "Parameter error");
        }
    }

}
