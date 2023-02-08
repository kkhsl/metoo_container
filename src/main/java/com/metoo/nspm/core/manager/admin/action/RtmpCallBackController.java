package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.ILiveRoomService;
import com.metoo.nspm.entity.nspm.LiveRoom;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * Title:
 * </p>
 *
 * <p>
 * Description: OBS 参数返回值
 * =======value: hls
 * =======key: app
 * 2021-04-10 15:52:26.161 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.162 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.163 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: FMLE/3.0 (compatible; FMSc/1.0)
 * =======key: flashver
 * 2021-04-10 15:52:26.164 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.165 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.165 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: rtmp://lk.soarmall.com/hls
 * =======key: swfurl
 * 2021-04-10 15:52:26.167 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.167 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.168 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: rtmp://lk.soarmall.com/hls
 * =======key: tcurl
 * 2021-04-10 15:52:26.169 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.169 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.171 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value:
 * =======key: pageurl
 * 2021-04-10 15:52:26.172 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.173 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.174 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: 113.240.131.200
 * =======key: addr
 * 2021-04-10 15:52:26.175 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.175 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.176 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: 166
 * =======key: clientid
 * 2021-04-10 15:52:26.178 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.178 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.179 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: publish
 * =======key: call
 * 2021-04-10 15:52:26.181 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.181 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.182 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: 202104076nC04q1
 * =======key: name
 * 2021-04-10 15:52:26.185 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==>  Preparing: SELECT * FROM metoo_room_program mrp WHERE status=? and live=?
 * 2021-04-10 15:52:26.185 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : ==> Parameters: 1(Integer), 0(Integer)
 * 2021-04-10 15:52:26.186 DEBUG 10656 --- [nio-8080-exec-4] c.h.c.c.m.RoomProgramMapper.condition    : <==      Total: 0
 * =======value: live
 * =======key: type
 * </p>
 */

@Api("OBS回调方法")
@RestController
@RequestMapping("/rtmp")
public class RtmpCallBackController {

    @Autowired
    private ILiveRoomService liveRoomService;

    @ApiOperation("OBS开启回调")
    @RequestMapping("/on_publish")
    public void onPublish(HttpServletRequest request) {
        String bindCode = null;
        Map<String, String[]> map = request.getParameterMap();
        //遍历
        for (Iterator iter = map.entrySet().iterator(); iter.hasNext(); ) {
            Map.Entry element = (Map.Entry) iter.next();
            //key值
            Object strKey = element.getKey();
            if (strKey != null && strKey.equals("name")) {
                //value,数组形式
                String[] value = (String[]) element.getValue();
                for (int i = 0; i < value.length; i++) {
                    if (value[i] != null && !value[i].equals("")) {
                        bindCode = value[i];
                    }
                }
            }
        }
        Map params = new HashMap();
        params.put("bindCode", bindCode);
        params.put("isEnable", 1);
        params.put("currentPage", 1);
        params.put("pageSize", 1);
        List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
        if (liveRoomList.size() > 0) {
            LiveRoom liveRoom = liveRoomList.get(0);
            liveRoom.setObs(1);
            this.liveRoomService.update(liveRoom);
        }

          /*  Map map = new HashMap();
            map.put("status", 1);
            map.put("live", 0);
            List<RoomProgram> roomProgramList = this.roomProgramService.findObjByCondition(map);
            if (roomProgramList.size() > 0) {
                RoomProgram roomProgram = roomProgramList.get(0);
                roomProgram.setLive(1);
                this.roomProgramService.update(roomProgramList.get(0));
            }*/
    }

    @ApiOperation("OBS关闭回调")
    @RequestMapping("/on_done")
    public void on_done(HttpServletRequest request) {
        try {
            Thread.sleep(15000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        Map<String, String[]> map = request.getParameterMap();
        String bindCode = null;
        //遍历
        for (Iterator iter = map.entrySet().iterator(); iter.hasNext(); ) {
            Map.Entry element = (Map.Entry) iter.next();
            //key值
            Object strKey = element.getKey();
            if (strKey != null && strKey.equals("name")) {
                //value,数组形式
                String[] value = (String[]) element.getValue();
                for (int i = 0; i < value.length; i++) {
                    if (value[i] != null && !value[i].equals("")) {
                        bindCode = value[i];
                    }
                }
            }
        }
        Map params = new HashMap();
        params.put("bindCode", bindCode);
        params.put("isEnable", 1);
        params.put("currentPage", 1);
        params.put("pageSize", 1);
        List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
        if (liveRoomList.size() > 0) {
            LiveRoom liveRoom = liveRoomList.get(0);
            liveRoom.setObs(0);
            this.liveRoomService.update(liveRoom);
        }
    }

}
