package com.metoo.nspm.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;
// Stash 10
// Stash 9
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class WebLiveRoomVo {

    private Long live_Room_id;

    private Date live_Room_addTime;

    private String live_Room_title;

    private String live_Room_info;

    private Integer live_Room_live;

    private Integer live_Room_obs;

    private Long room_program_id;

    private String room_program_title;

    private String room_program_roomId;

    private String room_program_lecturer;

    private String room_program_status;

    private Long ma_id;

    private String ma_name;

    private String ma_path;


    private Long grade_id;

    private String grade_name;

    private Long course_id;

    private String course_name;
}
