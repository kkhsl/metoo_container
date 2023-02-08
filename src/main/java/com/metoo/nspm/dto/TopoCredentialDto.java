package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.web.multipart.MultipartFile;

@Accessors
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TopoCredentialDto {

    private String id;
    private Integer pageIndex;
    private Integer pageSize;
    private String selectBox;
    private String branchLevel;
    private String enablePassword;
    private String enableUserName;
    private String enableName;
    private String loginName;
    private String loginPassword;
    private String name;
    private String uuid;
    private String version;
    private Boolean isReload;
    private Boolean isTrusted;

    public MultipartFile file;
    public String fileName;
    public Integer fileSize;
    public String encrypt;
    public String credentialId;

}
