package com.metoo.nspm.entity.nspm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class BackUp {

    private String key;
    private String value;
    private String ids;
    private String filename;
    private String fileName;
    private Integer fileSize;
    private String position;
    private String description;
    private Integer start;
    private Integer limit;
    private String ftpHost;
    private String ftpPort;
    private String ftpUser;
    private String ftpPassword;
    private String ftpFolder;
    private Integer enabled;
    private String obj1;
}
