package com.metoo.nspm.core.mapper.nspm;

import com.metoo.nspm.dto.CredentialDTO;
import com.metoo.nspm.entity.nspm.Credential;
import com.github.pagehelper.Page;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface CredentialMapper {

    Credential getObjById(Long id);

    Credential getObjByName(String name);

    List<Credential> query();

    int save(Credential instance);

    int update(Credential instance);

    int delete(Long id);

    public int batchesDel(Long[] ids);

    Page<Credential> getObjsByLevel(Credential instance);

    List<Credential> selectConditionQuery(CredentialDTO dto);

    List<Credential> getAll();
}
