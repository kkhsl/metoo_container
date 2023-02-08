package com.metoo.nspm.core.ssh.excutor;

import java.util.Date;

public class ExecutorDto {
    private String id;
    private String name;
    private String description;
    private Date createTime;

    public ExecutorDto(String id, String name, String description, Date createTime) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.createTime = createTime;
    }

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Date getCreateTime() {
        return this.createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getSimpleName());
        sb.append(" [");
        sb.append("id=").append(this.id);
        sb.append(", name=").append(this.name);
        sb.append(", description=").append(this.description);
        sb.append(", createTime=").append(this.createTime);
        sb.append("]");
        return sb.toString();
    }
}
