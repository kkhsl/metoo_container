package com.metoo.nspm.core.manager.admin.tools;

import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.video.VideoUtil;
import com.metoo.nspm.entity.nspm.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Date;

@Component
public class PlayBackTools {


    @Autowired
    private ISysConfigService sysConfigService;

    @Autowired
    private IProgramPlaybackService programPlaybackService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private IRoomProgramService roomProgramService;
    @Autowired
    private IVideoService videoService;
    @Autowired
    private ISysConfigService configService;

    /**
     * 创建回放
     * @param live
     * @param program
     * @param bindCode
     * @return
     */
    public boolean create(Long live, RoomProgram program, String bindCode){
        User user = ShiroUserHolder.currentUser();
        SysConfig sysconfig = this.sysConfigService.select();
        String currentDate = CommUtils.formatTime("yyyyMMddHHmmss", new Date());
        SysConfig configs = this.configService.select();
        String uploaFilePath = configs.getUploadFilePath() + File.separator + "video";
        String path = sysconfig.getPath() + File.separator + bindCode;
//        String playback = path + File.separator + currentDate;
        String playback =  configs.getVideoFilePath();
        String name =  program.getId() + "-" + currentDate;
        boolean flag =  VideoUtil.ConvertMp4(path, playback, name);
        if(flag){
            String rtmp = CommUtils.getRtmp(sysconfig.getIp(), bindCode)+ File.separator + currentDate;// 回放视频路径
             // 保存回放文件信息
            Accessory accessory = new Accessory();
            accessory.setA_name(name + ".mp4");
            accessory.setA_path(uploaFilePath);
            accessory.setA_ext("mp4");
            accessory.setA_size(-1);
            accessory.setType(2);
            this.accessoryService.save(accessory);
            // 创建回放文件对象
            Video video = new Video();
            video.setAddTime(new Date());
            video.setName(program.getTitle());
            video.setBeginTime(CommUtils.formatTime("yyyy-MM-dd HH:mm:ss", program.getBeginTime()));
            video.setEndTime(CommUtils.formatTime("yyyy-MM-dd HH:mm:ss", program.getEndTime()));
            video.setGrade(program.getGrade());
            video.setCourse(program.getCourse());
            // 视频审核
            SysConfig sysConfigList = sysConfigService.select();
            if(sysConfigList.getVideoAudit()==0){
                video.setStatus(1);
            }else{
                video.setStatus(0);
            }

            video.setDisplay(1);
            video.setType(1);
            video.setSequence(0);
            video.setVideo(accessory);
            video.setUserId(user.getId());
            video.setUserName(user.getUsername());
            video.setLecturer(program.getLecturer());
            video.setRoomProgramId(program.getId());
            video.setLiveRoomId(program.getRoomId());
            this.videoService.save(video);

        }
        return false;
    }
}
