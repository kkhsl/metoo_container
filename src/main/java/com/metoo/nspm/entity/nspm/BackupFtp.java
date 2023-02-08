package com.metoo.nspm.entity.nspm;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class BackupFtp {

    private String id;
    private String ftpHost;
    private String ftpPort;
    private String ftpUser;
    private String ftpPassword;
    private String ftpTimeout;
    private String ftpFolder;
    private String enabled;
    private String description;
    @DateTimeFormat(
            pattern = "yyyy-MM-dd HH:mm:ss"
    )
    @JsonFormat(
            timezone = "GMT+8",
            pattern = "yyyy-MM-dd HH:mm:ss"
    )
    private Date createTime;
    private String obj1;
    private String obj2;
    private String obj3;
    private static final long serialVersionUID = 1L;
}
