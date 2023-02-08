package com.metoo.nspm.vo;


import io.swagger.annotations.ApiModel;
import lombok.*;

/*@EqualsAndHashCode //实现equals()和hashCode()
@ToString  //实现toString()*/
/*@Cleanup  //关闭流
@Synchronized //对象上同步
@SneakyThrows //抛出异常*/
@NoArgsConstructor  //注解在类上；为类提供一个无参的构造方法
@AllArgsConstructor  //注解在类上；为类提供一个全参的构造方法
@Data  //注解在类上；提供类所有属性的 getting 和 setting 方法，此外还提供了equals、canEqual、hashCode、toString 方法
@Setter  //可用在类或属性上；为属性提供 setting 方法
@Getter  //可用在类或属性上；为属性提供 getting 方法
public class SysConfigVo {

    private Long id;
    private String ntasUrl;
    private String ntasToken;

}
