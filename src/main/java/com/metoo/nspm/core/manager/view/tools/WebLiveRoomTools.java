package com.metoo.nspm.core.manager.view.tools;

import com.metoo.nspm.core.service.nspm.IRoomProgramService;
import com.metoo.nspm.entity.nspm.RoomProgram;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class WebLiveRoomTools {

    @Autowired
    private IRoomProgramService roomProgramService;

    public boolean exists(Long id){
        Map params = new HashMap();
        params.put("roomId", id);
        params.put("status", 1);
        List<RoomProgram> roomPrograms = this.roomProgramService.findObjByCondition(params);
        if(roomPrograms.size()>0){
            return false;
        }
        return true;
    }
}
